package ehframe

import(
	"debug/elf"
	"testing"
)

const testprogram = "testprograms/naccess"

func Test_raddr(t *testing.T) {
	legolas, err := elf.Open(testprogram)
	if err != nil {
		t.Fatalf("could not open %s: %v", testprogram, err)
	}
	defer legolas.Close()

	frame := legolas.Section(".eh_frame")
	ehframe, err := section(testprogram, frame.Offset, frame.Size)
	if err != nil {
		t.Fatalf("could not read .eh_frame: %v", err)
	}

	cfa, err := RetAddrAddr(0x400550, ehframe, frame.Offset)
	if err != nil {
		t.Fatalf("could not get retaddr for 0x400550: %v", err)
	}
	if cfa.Reg != Rsp {
		t.Fatalf("incorrect register: was %v, should be %v", cfa.Reg, Rsp)
	}
	if cfa.Offset != 8 {
		t.Fatalf("incorrect offset: was %d, should be %d", cfa.Offset, 8)
	}
}
