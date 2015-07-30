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
package ehframe

import(
	"fmt"
)

type interpreter interface {
	Exec(Inst) error
}

type Dwarfx8664Reg uint
const(
	rax Dwarfx8664Reg = 0
	rdx Dwarfx8664Reg = iota
	rcx Dwarfx8664Reg = iota
	rbx Dwarfx8664Reg = iota
	rsi Dwarfx8664Reg = iota
	rdi Dwarfx8664Reg = iota
	rbp Dwarfx8664Reg = iota
	rsp Dwarfx8664Reg = iota
	r8 Dwarfx8664Reg = 8 // neat.
	r9 Dwarfx8664Reg = iota
	r10 Dwarfx8664Reg = iota
	r11 Dwarfx8664Reg = iota
	r12 Dwarfx8664Reg = iota
	r13 Dwarfx8664Reg = iota
	r14 Dwarfx8664Reg = iota
	r15 Dwarfx8664Reg = iota
	rAddr Dwarfx8664Reg = iota // AFAICT this is not a real register.
	xmm0 Dwarfx8664Reg = 17
	xmm1 Dwarfx8664Reg = iota
	xmm2 Dwarfx8664Reg = iota
	xmm3 Dwarfx8664Reg = iota
	xmm4 Dwarfx8664Reg = iota
	xmm5 Dwarfx8664Reg = iota
	xmm6 Dwarfx8664Reg = iota
	xmm7 Dwarfx8664Reg = iota
	xmm8 Dwarfx8664Reg = iota
	xmm9 Dwarfx8664Reg = iota
	xmm10 Dwarfx8664Reg = iota
	xmm11 Dwarfx8664Reg = iota
	xmm12 Dwarfx8664Reg = iota
	xmm13 Dwarfx8664Reg = iota
	xmm14 Dwarfx8664Reg = iota
	xmm15 Dwarfx8664Reg = iota
	st0 Dwarfx8664Reg = 33
	st1 Dwarfx8664Reg = iota
	st2 Dwarfx8664Reg = iota
	st3 Dwarfx8664Reg = iota
	st4 Dwarfx8664Reg = iota
	st5 Dwarfx8664Reg = iota
	st6 Dwarfx8664Reg = iota
	st7 Dwarfx8664Reg = iota
	mm0 Dwarfx8664Reg = 41 // i.e. MMX
	mm1 Dwarfx8664Reg = iota
	mm2 Dwarfx8664Reg = iota
	mm3 Dwarfx8664Reg = iota
	mm4 Dwarfx8664Reg = iota
	mm5 Dwarfx8664Reg = iota
	mm6 Dwarfx8664Reg = iota
	mm7 Dwarfx8664Reg = iota
	rFlags Dwarfx8664Reg = 49
)
func (reg Dwarfx8664Reg) String() string {
	switch(reg) {
	case rax: return "%rax"
	case rdx: return "%rdx"
	case rcx: return "%rcx"
	case rbx: return "%rbx"
	case rsi: return "%rsi"
	case rdi: return "%rdi"
	case rbp: return "%rbp"
	case rsp: return "%rsp"
	case r8: return "%r8"
	case r9: return "%r9"
	case r10: return "%r10"
	case r11: return "%r11"
	case r12: return "%r12"
	case r13: return "%r13"
	case r14: return "%r14"
	case r15: return "%r15"
	case rAddr: return "%r16"
	case xmm0: return "%xmm0"
	case xmm1: return "%xmm1"
	case xmm2: return "%xmm2"
	case xmm3: return "%xmm3"
	case xmm4: return "%xmm4"
	case xmm5: return "%xmm5"
	case xmm6: return "%xmm6"
	case xmm7: return "%xmm7"
	case xmm8: return "%xmm8"
	case xmm9: return "%xmm9"
	case xmm10: return "%xmm10"
	case xmm11: return "%xmm11"
	case xmm12: return "%xmm12"
	case xmm13: return "%xmm13"
	case xmm14: return "%xmm14"
	case xmm15: return "%xmm15"
	case st0: return "%st0"
	case st1: return "%st1"
	case st2: return "%st2"
	case st3: return "%st3"
	case st4: return "%st4"
	case st5: return "%st5"
	case st6: return "%st6"
	case st7: return "%st7"
	case mm0: return "%mmx0"
	case mm1: return "%mmx1"
	case mm2: return "%mmx2"
	case mm3: return "%mmx3"
	case mm4: return "%mmx4"
	case mm5: return "%mmx5"
	case mm6: return "%mmx6"
	case mm7: return "%mmx7"
	case rFlags: return "%rflags"
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
			assert(uint(ixn.Oper[0].(register)) <= uint(rFlags)) // unknown reg?
			reg := Dwarfx8664Reg(uint(ixn.Oper[0].(register)))
			if reg <= r15 { // ignore irrelevant registers.
				dvm.CFA = UndefinedCFA{Register: reg}
			}
		case CFA_def_cfa:
			assert(uint(ixn.Oper[0].(register)) <= uint(rFlags)) // unknown reg?
			dvm.CFA = RegCFA{Register: Dwarfx8664Reg(uint(ixn.Oper[0].(register))),
			                 Offset: int(ixn.Oper[1].(Offset))}
		case CFA_def_cfa_offset:
			reg, is_reg := dvm.CFA.(RegCFA)
			assert(is_reg) // only valid when current rule is a RegCFA rule.
			dvm.CFA = RegCFA{Register: reg.Register,
			                 Offset: int(ixn.Oper[0].(Offset)) * code_align}
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
			dvm.CFA = RegCFA{Register: Dwarfx8664Reg(uint(ixn.Oper[0].(register))),
			                 Offset: reg.Offset}
		default:
			return fmt.Errorf("unhandled opcode %v", ixn.Op)
		}
	} else if ixn.Op < CFA_offset {
		offs := int(ixn.Oper[0].(Offset))
		assert(offs > 0) // addresses only increase.
		dvm.Location += uintptr(offs * code_align)
	} else if ixn.Op < CFA_restore {
		assert(uint(ixn.Oper[0].(register)) <= uint(rFlags)) // unknown reg?
		reg := Dwarfx8664Reg(uint(ixn.Oper[0].(register)))
		if reg <= r15 {
			dvm.CFA = RegCFA{Register: Dwarfx8664Reg(uint(ixn.Oper[0].(register))),
			                 Offset: int(ixn.Oper[1].(Offset)) * code_align}
		}
	} else {
		return fmt.Errorf("Unhandled instruction %v", ixn)
	}
	return nil
}
