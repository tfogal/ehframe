// To accurately unwind the stack, a debugger needs detailed information on how
// to both find the return address as well as reset the contents of machine
// registers.  As described elsewhere, one cannot rely on a particular
// register to have this information as x86-64 omits the frame pointer and the
// stack pointer changes throughout the execution of the function.
//
// The natural solution is to store a key-value table, where each key is an
// instruction address and each value is, say, an encoded expression (offset
// off of the stack pointer, perhaps?).  Then our fearless debugger need only
// find & decode the value for the current instruction pointer, compute a memory
// address from a register and an offset of the value in that register, and
// read that memory location---the return address.
// 
// The DWARF folks thought it fitting to go the extra mile.  Instead of a simple
// offset, the values in the table are a sequence of *instructions* in a
// Turing-complete stack-based virtual machine.  Debuggers must therefore
// interpret the virtual machine's instructions to compute values such as the
// return address.  The plus side of this approach is that it is possible to
// encode information on callee-saved registers that must be restored (that
// said, it's unclear why a Turing-complete language was necessary, as opposed
// to a simple table).
//
// This implements the parsing of DWARF's virtual machine instruction set.
//
// There are some "gotcha"s.  An entry for every single instruction in a
// program or shared library would be massive; the table is compressed.
// Furthermore, the table is subject to alignment requirements, and therefore
// tends to end with a series of NOPs.
package main
import "fmt"

type Program struct {
  stream []byte
  data_align uint
  code_align uint
}

type Opcode uint
const(
  // These define ranges of opcodes.  All "real" values are below
  // CFA_advance_loc; for values above it, it seems that the byte itself
  // becomes part of the operand of the instruction.
  CFA_advance_loc Opcode = 0x40
  CFA_offset Opcode = 0x80
  CFA_restore Opcode = 0xc0
  //CFA_extended Opcode = 0xff

  CFA_nop Opcode = 0x00
  CFA_set_loc Opcode = 0x01
  CFA_advance_loc1 Opcode = 0x02
  CFA_advance_loc2 Opcode = 0x03
  CFA_advance_loc4 Opcode = 0x04
  CFA_offset_extended Opcode = 0x05
  CFA_restore_extended Opcode = 0x06
  CFA_undefined Opcode = 0x07
  CFA_same_value Opcode = 0x08
  CFA_register Opcode = 0x09
  CFA_remember_state Opcode = 0x0a
  CFA_restore_state Opcode = 0x0b
  CFA_def_cfa Opcode = 0xc
  CFA_def_cfa_register Opcode = 0x0d
  CFA_def_cfa_offset Opcode = 0x0e
  CFA_def_cfa_expression Opcode = 0x0f
  CFA_expression Opcode = 0x10
  CFA_offset_extended_sf Opcode = 0x11
  CFA_def_cfa_sf Opcode = 0x12
  CFA_def_cfa_offset_sf Opcode = 0x13
  CFA_val_offset Opcode = 0x14
  CFA_val_offset_sf Opcode = 0x15
  CFA_val_expression Opcode = 0x16

  CFA_low_user Opcode = 0x1c
  CFA_MIPS_advance_loc8 Opcode = 0x1d
  CFA_GNU_window_save Opcode = 0x2d
  CFA_GNU_args_size Opcode = 0x2e
  CFA_GNU_negative_offset_extended Opcode = 0x2f
  CFA_high_user Opcode = 0x3f
)

func (op Opcode) String() string {
  if op < CFA_advance_loc {
    switch(op) {
    case CFA_nop: return "nop"
    case CFA_set_loc: return "set_loc"
    case CFA_advance_loc1: return "advance_loc1"
    case CFA_advance_loc2: return "advance_loc2"
    case CFA_advance_loc4: return "advance_loc4"
    case CFA_offset_extended: return "offset_extended"
    case CFA_restore_extended: return "restore_extended"
    case CFA_undefined: return "undefined"
    case CFA_same_value: return "same_value"
    case CFA_register: return "register"
    case CFA_remember_state: return "remember_state"
    case CFA_restore_state: return "restore_state"
    case CFA_def_cfa: return "def_cfa"
    case CFA_def_cfa_register: return "def_cfa_register"
    case CFA_def_cfa_offset: return "def_cfa_offset"
    case CFA_def_cfa_expression: return "def_cfa_expression"
    case CFA_expression: return "expression"
    case CFA_offset_extended_sf: return "offset_extended_sf"
    case CFA_def_cfa_sf: return "def_cfa_sf"
    case CFA_def_cfa_offset_sf: return "def_cfa_offset_sf"
    case CFA_val_offset: return "val_offset"
    case CFA_val_offset_sf: return "val_offset_sf"
    case CFA_val_expression: return "val_expression"
    case CFA_low_user: return "low_user"
    case CFA_MIPS_advance_loc8: return "MIPS_advance_loc8"
    case CFA_GNU_window_save: return "GNU_window_save"
    case CFA_GNU_args_size: return "GNU_args_size"
    case CFA_GNU_negative_offset_extended: return "negative_offset_extended"
    case CFA_high_user: return "high_user"
    default:
      return "unknown advance_loc"
    }
  } else if op < CFA_advance_loc {
    return "unknown advance_loc"
  } else if op < CFA_offset {
    return "advance_loc"
  } else if op < CFA_restore {
    return "offset"
  }
  return "restore"
}

type Operand interface {
  String() string
}
type Register uint
func (r Register) String() string {
  return fmt.Sprintf("reg(%d)", uint(r))
}
type Offset int
func (o Offset) String() string {
  return fmt.Sprintf("offset %d", int(o))
}

// An Inst is a single DWARF CFA instruction.
type Inst struct {
  Op Opcode
  Oper [2]Operand
  Len uint         // length of the instruction, in bytes.
}
func (ixn Inst) String() string {
  return fmt.Sprintf("0x%02x %v(%v, %v)", uint(ixn.Op), ixn.Op,
                     ixn.Oper[0], ixn.Oper[1])
}

func Decode(insn []byte, code_align int, data_align int) Inst {
  rv := Inst{Op: Opcode(insn[0])}
  rv.Len = 1 // best guess if we don't know.
  if rv.Op < CFA_advance_loc {
    switch rv.Op {
    case CFA_def_cfa:
      op1, nbytes := uleb128(insn[1:1+16])
      op2, nb := uleb128(insn[1+nbytes:1+nbytes+16])
      rv.Oper[0] = Register(op1)
      rv.Oper[1] = Offset(op2)
      rv.Len = 1 + nbytes + nb
    case CFA_undefined:
      r, nbytes := uleb128(insn[1:1+16])
      rv.Oper[0] = Register(r)
      rv.Len = 1 + nbytes
    case CFA_def_cfa_offset:
      offs, nb := uleb128(insn[1:1+16])
      rv.Oper[0] = Offset(offs)
      rv.Len = 1 + nb
    case CFA_def_cfa_expression:
      len, nb := uleb128(insn[1:1+16])
      rv.Len = 1 + nb + uint(len)
    case CFA_def_cfa_register:
      reg, nb := uleb128(insn[1:1+16])
      rv.Oper[0] = Register(reg)
      rv.Len = 1 + nb
    case CFA_advance_loc1:
      offs := uint(insn[1])
      rv.Oper[0] = Offset(offs)
      rv.Len = 1 + 1
    case CFA_advance_loc2:
      offs := assembleu16(insn[1:3])
      rv.Oper[0] = Offset(offs)
      rv.Len = 1 + 2
    case CFA_advance_loc4:
      offs := assembleu32(insn[1:5])
      rv.Oper[0] = Offset(offs)
      rv.Len = 1 + 4
    }
  } else if rv.Op < CFA_offset {
    rv.Oper[0] = Offset(insn[0] & 0x3f)
    rv.Len = 1
  } else if rv.Op < CFA_restore {
    op1, nbytes := uleb128(insn[1:1+16])
    rv.Oper[0] = Register(rv.Op & 0x3f)
    rv.Oper[1] = Offset(int(op1) * int(data_align))
    rv.Len = 1 + nbytes
  }
  return rv
}
