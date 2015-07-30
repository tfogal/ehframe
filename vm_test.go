package ehframe

import(
	"debug/elf"
	"testing"
)

// Very simple test that just grabs the first CIE from "/bin/true" and executes
// the program in that CIE.
func TestTrueFirstCIE(t *testing.T) {
	fname := "/bin/true"
	legolas, err := elf.Open(fname)
	if err != nil {
		t.Fatalf("could not open '%s': %s\n", fname, err)
	}
	defer legolas.Close()

	frame := legolas.Section(".eh_frame")
	CFIs, err := section(fname, frame.Offset, frame.Size)
	if err != nil {
		t.Fatalf("could not read .eh_frame: %v\n", err)
	}

	rdr := Start(CFIs)
	cfi, err := rdr.Next()
	if err != nil {
		t.Fatalf("%v", err)
	}
	cie, is_cie := cfi.(CIE)
	if !is_cie {
		t.Fatalf("first entry is not a CIE!")
	}

	program := cie.Program
	offset := uint(0)
	cal := cie.CodeAlign
	dal := cie.DataAlign
	vm := DwarfVM{}
	for offset < uint(len(program)) && program[offset] != 0x0 {
		ixn := Decode(program[offset:])
		if err := vm.Exec(ixn, cal, dal); err != nil {
			t.Fatalf("error executing '%v': %v", ixn, err)
		}
		offset += ixn.Len
	}
}

// Runs through every FDE of our test program and executes the program.
func TestAccessAllFDE(t *testing.T) {
	fname := "./testprograms/naccess"
	legolas, err := elf.Open(fname)
	if err != nil {
		t.Fatalf("could not open '%s': %s\n", fname, err)
	}
	defer legolas.Close()

	frame := legolas.Section(".eh_frame")
	CFIs, err := section(fname, frame.Offset, frame.Size)
	if err != nil {
		t.Fatalf("could not read .eh_frame: %v\n", err)
	}

	rdr := Start(CFIs)
	for cfi, err := rdr.Next(); err == nil; cfi, err = rdr.Next() {
		fde, is_fde := cfi.(FDE)
		if !is_fde { // just skip it, we only use CIEs as associated to FDEs.
			continue
		}
		cal := fde.Associated.CodeAlign
		dal := fde.Associated.DataAlign
		vm := DwarfVM{}
		initial := fde.Associated.Program
		offset := uint(0)

		for offset < uint(len(initial)) && initial[offset] != 0x0 {
			ixn := Decode(initial[offset:])
			if err := vm.Exec(ixn, cal, dal); err != nil {
				t.Fatalf("error executing CIE insn '%v': %v", ixn, err)
			}
			offset += ixn.Len
		}

		program := fde.Program
		offset = 0

		for offset < uint(len(program)) && program[offset] != 0x0 {
			ixn := Decode(program[offset:])
			if err := vm.Exec(ixn, cal, dal); err != nil {
				t.Fatalf("error executing FDE insn '%v': %v", ixn, err)
			}
			offset += ixn.Len
		}
	}
}
