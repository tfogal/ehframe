// DwarfVM defines a simple interpreter for the virtual machine defined in the
// 'exception handling' part of the DWARF specification.
//
// The virtual machine is used to encode where the return address is located as
// well as how to reset registers, should execution need to suddenly 'jump'
// back up the stack.  Such extensive information is needed for exception
// handling; we only care about debugging, and thus the return address.
// Further, we only care about one level of "unwinding", as this process is
// called.  Thus, we completely ignore any register information.
//
// Nonetheless, this implements a simple interpreter that will allow querying
// the call frame address ("CFA") after executing any number of DWARF VM
// instructions.  Vaguely, usage is:
//
//   var program []byte
//   program = ... source of program ...
//   beginning := uint(... offset within binary of the FDE or CIE ...)
//   offset := uint(0)
//   interp := DwarfVM{}
//   for offset < uint(len(program)) && program[offset] != 0x0 {
//     ixn := Decode(program[offset:], ...)
//     interp.Exec(ixn)
//     if beginning + interp.Location == address_of_interest {
//       return interp.CFA
//     }
//     offset += ixn.Len
//   }
//
// "beginning" is difficult to describe because it is external state and DWARF
// has many ways to compute it.  Basically, every DWARF VM program applies to
// an externally-supplied region of code; the 'Location' value we track only
// specifies the offset relative to the start of this region.  Thus, you'll
// need to account for identifying that region in other code.
package main

import(
	"fmt"
)

type interpreter interface {
	Exec(Inst) error
}

type Dwarfx8664Reg uint
const(
	Rax Dwarfx8664Reg = 0
	Rdx Dwarfx8664Reg = iota
	Rcx Dwarfx8664Reg = iota
	Rbx Dwarfx8664Reg = iota
	Rsi Dwarfx8664Reg = iota
	Rdi Dwarfx8664Reg = iota
	Rbp Dwarfx8664Reg = iota
	Rsp Dwarfx8664Reg = iota
	R8 Dwarfx8664Reg = 8 // neat.
	R9 Dwarfx8664Reg = iota
	R10 Dwarfx8664Reg = iota
	R11 Dwarfx8664Reg = iota
	R12 Dwarfx8664Reg = iota
	R13 Dwarfx8664Reg = iota
	R14 Dwarfx8664Reg = iota
	R15 Dwarfx8664Reg = iota
	RAddr Dwarfx8664Reg = iota // AFAICT this is not a real register.
	Xmm0 Dwarfx8664Reg = 17
	Xmm1 Dwarfx8664Reg = iota
	Xmm2 Dwarfx8664Reg = iota
	Xmm3 Dwarfx8664Reg = iota
	Xmm4 Dwarfx8664Reg = iota
	Xmm5 Dwarfx8664Reg = iota
	Xmm6 Dwarfx8664Reg = iota
	Xmm7 Dwarfx8664Reg = iota
	Xmm8 Dwarfx8664Reg = iota
	Xmm9 Dwarfx8664Reg = iota
	Xmm10 Dwarfx8664Reg = iota
	Xmm11 Dwarfx8664Reg = iota
	Xmm12 Dwarfx8664Reg = iota
	Xmm13 Dwarfx8664Reg = iota
	Xmm14 Dwarfx8664Reg = iota
	Xmm15 Dwarfx8664Reg = iota
	St0 Dwarfx8664Reg = 33
	St1 Dwarfx8664Reg = iota
	St2 Dwarfx8664Reg = iota
	St3 Dwarfx8664Reg = iota
	St4 Dwarfx8664Reg = iota
	St5 Dwarfx8664Reg = iota
	St6 Dwarfx8664Reg = iota
	St7 Dwarfx8664Reg = iota
	Mm0 Dwarfx8664Reg = 41 // i.e. MMX
	Mm1 Dwarfx8664Reg = iota
	Mm2 Dwarfx8664Reg = iota
	Mm3 Dwarfx8664Reg = iota
	Mm4 Dwarfx8664Reg = iota
	Mm5 Dwarfx8664Reg = iota
	Mm6 Dwarfx8664Reg = iota
	Mm7 Dwarfx8664Reg = iota
	RFlags Dwarfx8664Reg = 49
)
func (reg Dwarfx8664Reg) String() string {
	switch(reg) {
	case Rax: return "%rax"
	case Rdx: return "%rdx"
	case Rcx: return "%rcx"
	case Rbx: return "%rbx"
	case Rsi: return "%rsi"
	case Rdi: return "%rdi"
	case Rbp: return "%rbp"
	case Rsp: return "%rsp"
	case R8: return "%r8"
	case R9: return "%r9"
	case R10: return "%r10"
	case R11: return "%r11"
	case R12: return "%r12"
	case R13: return "%r13"
	case R14: return "%r14"
	case R15: return "%r15"
	case RAddr: return "%r16"
	case Xmm0: return "%xmm0"
	case Xmm1: return "%xmm1"
	case Xmm2: return "%xmm2"
	case Xmm3: return "%xmm3"
	case Xmm4: return "%xmm4"
	case Xmm5: return "%xmm5"
	case Xmm6: return "%xmm6"
	case Xmm7: return "%xmm7"
	case Xmm8: return "%xmm8"
	case Xmm9: return "%xmm9"
	case Xmm10: return "%xmm10"
	case Xmm11: return "%xmm11"
	case Xmm12: return "%xmm12"
	case Xmm13: return "%xmm13"
	case Xmm14: return "%xmm14"
	case Xmm15: return "%xmm15"
	case St0: return "%st0"
	case St1: return "%st1"
	case St2: return "%st2"
	case St3: return "%st3"
	case St4: return "%st4"
	case St5: return "%st5"
	case St6: return "%st6"
	case St7: return "%st7"
	case Mm0: return "%mmx0"
	case Mm1: return "%mmx1"
	case Mm2: return "%mmx2"
	case Mm3: return "%mmx3"
	case Mm4: return "%mmx4"
	case Mm5: return "%mmx5"
	case Mm6: return "%mmx6"
	case Mm7: return "%mmx7"
	case RFlags: return "%rflags"
	}
	return fmt.Sprintf("unknown reg %d", uint(reg))
}

type CallFrameAddr interface {
	String() string
}

type RegCFA struct {
	Register Dwarfx8664Reg
	Offset int
}

func (r RegCFA) String() string {
	return fmt.Sprintf("cfa %v:%d", r.Register, r.Offset)
}

// There is an explicit instruction in the DWARF VM that says, "this register
// is not defined".
type UndefinedCFA struct {
	Register Dwarfx8664Reg
}
func (u UndefinedCFA) String() string {
	return fmt.Sprintf("undef %v", u.Register)
}

type DwarfVM struct {
	Location uintptr
	CFA CallFrameAddr
}

func (dvm *DwarfVM) Exec(ixn Inst, code_align int, data_align int) error {
	// TODO/FIXME: check the register in these instructions.  If it's not the
	// return address register, we should ignore it.
	// Not 100% sure that'll work out in practice: is it possible to define the
	// return address register in terms of another register?  If so, we'd need to
	// track all registers.
	// In any case, the way we're doing it now essentially just tracks 'the last
	// register set', which of course is only our return address reg if we are
	// really lucky.
	if ixn.Op < CFA_advance_loc {
	  switch(ixn.Op) {
		case CFA_undefined:
			assert(uint(ixn.Oper[0].(Register)) <= uint(RFlags)) // unknown reg?
			reg := Dwarfx8664Reg(uint(ixn.Oper[0].(Register)))
			dvm.CFA = UndefinedCFA{Register: reg}
	  case CFA_def_cfa:
			assert(uint(ixn.Oper[0].(Register)) <= uint(RFlags)) // unknown reg?
			dvm.CFA = RegCFA{Register: Dwarfx8664Reg(uint(ixn.Oper[0].(Register))),
			                 Offset: int(ixn.Oper[1].(Offset))}
		case CFA_def_cfa_offset:
			reg, is_reg := dvm.CFA.(RegCFA)
			assert(is_reg) // only valid when current rule is a RegCFA rule.
			dvm.CFA = RegCFA{Register: reg.Register,
			                 Offset: int(ixn.Oper[0].(Offset))}
		case CFA_advance_loc1:
			inc, ok := ixn.Oper[0].(Offset)
			if !ok {
				return fmt.Errorf("cannot convert %v to int", ixn.Oper[0])
			}
			incr := int(inc)
			assert(incr > 0) // is this true? seems like the address should only ++
			dvm.Location += uintptr(incr)
		case CFA_def_cfa_expression:
			fmt.Println("ignoring def_cfa_expression... hope this is okay")
		case CFA_def_cfa_register:
			reg, is_reg := dvm.CFA.(RegCFA)
			assert(is_reg) // insn only valid when current rule is already a RegCFA
			dvm.CFA = RegCFA{Register: Dwarfx8664Reg(uint(ixn.Oper[0].(Register))),
			                 Offset: reg.Offset}
		default:
			return fmt.Errorf("unhandled opcode %v", ixn.Op)
		}
	} else if ixn.Op < CFA_offset {
		offs := int(ixn.Oper[0].(Offset))
		assert(offs > 0) // addresses only increase.
		dvm.Location += uintptr(offs * code_align)
	} else if ixn.Op < CFA_restore {
		assert(uint(ixn.Oper[0].(Register)) <= uint(RFlags)) // unknown reg?
		dvm.CFA = RegCFA{Register: Dwarfx8664Reg(uint(ixn.Oper[0].(Register))),
		                 Offset: int(ixn.Oper[1].(Offset)) * data_align}
	} else {
		return fmt.Errorf("Unhandled instruction %v", ixn)
	}
	return nil
}
