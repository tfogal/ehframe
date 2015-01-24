package main

import(
	"errors"
	"fmt"
)

var(
	EOF = errors.New("end of file")
)

type Register uint
const(
	Rax Register = 0
	Rdx Register = iota
	Rcx Register = iota
	Rbx Register = iota
	Rsi Register = iota
	Rdi Register = iota
	Rbp Register = iota
	Rsp Register = iota
	R8 Register = 8
	R9 Register = iota
	R10 Register = iota
	R11 Register = iota
	R12 Register = iota
	R13 Register = iota
	R14 Register = iota
	R15 Register = iota
)
type CFA struct {
	Reg Register
	Offset int
}

// returns the address where the return address is stored.  The caller would
// still need to read that from the inferior.
// This returns the "CFA" (canonical frame address) for the given address
// (which should be an instruction address).  The return address is stored
// here: the caller must read the inferior's memory at the CFA to obtain the
// actual return address.
// The elf.Section should be the ".eh_frame" section, in its entirety.
// The offset is the offset from the start of the ELF that .eh_frame begins.
func RetAddrAddr(address uintptr, ehframe []byte, ehOff uint64) (CFA, error) {
	raddr_addr, err := cfa(address, ehframe, ehOff)
	if err != nil {
		return CFA{}, err
	}
	return raddr_addr, nil
}

func bounds(fde FDE, frameoff uint64) (uintptr, uintptr) {
	switch fde.Associated.Application {
	case Relative:
		beg := relative(fde.Offset[0], frameoff, 0x400000)
		end := relative(fde.Offset[1], frameoff, 0x400000)
		return beg, end
	}
	return 0x0, 0x0
}

func to_cfa(dwf CallFrameAddr) CFA {
	switch cfa := dwf.(type) {
	case RegCFA:
		if cfa.Register > r15 {
			panic("CFA can only be based on 'core' registers.")
		}
		return CFA{Reg: Register(cfa.Register), Offset: cfa.Offset}
	case UndefinedCFA:
		panic("CFA is currently undefined!")
	}
	panic("unhandled case")
}

func exec_program(program []byte, dvm *DwarfVM, calign int, dalign int) {
	offset := uint(0)
	for offset < uint(len(program)) && program[offset] != 0x0 /*nop*/ {
		ixn := Decode(program[offset:])
		dvm.Exec(ixn, calign, dalign)
		offset += ixn.Len
	}
}

func cfa(address uintptr, ehframe []byte, frameOffset uint64) (CFA, error) {
	fde, err := find_fde(address, ehframe, frameOffset)
	if err != nil {
		return CFA{}, err
	}
	beg, end := bounds(fde, frameOffset)
	assert(beg <= address && address <= end)

	program := fde.Program
	offset := uint(0)
	interp := DwarfVM{}
	cal := fde.Associated.CodeAlign
	dal := fde.Associated.DataAlign

	exec_program(fde.Associated.Program, &interp, cal, dal)

	if beg + interp.Location == address {
		return to_cfa(interp.CFA), nil
	}
	for offset < uint(len(program)) && program[offset] != 0x0 /*nop*/ {
		ixn := Decode(program[offset:])
		interp.Exec(ixn, cal, dal)
		if beg + interp.Location == address {
			return to_cfa(interp.CFA), nil
		}
		offset += ixn.Len
	}
	return CFA{}, fmt.Errorf("address 0x%x not found?", address)
}

func find_fde(address uintptr, ehframe []byte, frameOffs uint64) (FDE, error) {
	rdr := Start(ehframe)
	for cie, err := rdr.Next(); err == nil; cie, err = rdr.Next() {
		fde, is_fde := cie.(FDE)
		if !is_fde {
			continue
		}
		beg, end := bounds(fde, frameOffs)
		if beg <= address && address < end {
			return fde, nil
		}
	}
	return FDE{}, EOF
}
