// This is a program that parses the call frame information for a given
// DWARF-based object file.  The Go libraries do not (yet?) provide access to
// this information.
//
// The basic problem is that some architecture ABIs, such as x86-64, do not
// reserve a register for tracking the stack.  Thus, from an arbitrary
// instruction location, it is impossible to identify the return address.
// Since a debugger (and other applications, e.g. a profiler) *need* this
// information, the ELF/DWARF/x86-64 ABI solution was to add an extra section
// to executables for storing this.  The solution was complicated: the group
// defining the ABI decided this should go in an ELF section named
// .debug_frame, and furthermore, to omit that section when the application is
// not built with debugging information.  Except, wait, one needs this stuff to
// do C++-style exception handling!  So they defined *another* section,
// .eh_frame, that is defined to hold *almost* the same information, except
// with some minor changes to headers and some field widths and the like.
// This EH information is *always* present: this author's guess is that the
// information is needed even if an exception can be thrown *through* a
// function.  Sooo.... basically all functions.  Even ones that aren't C++
// functions.
//
// The author has never implemented exception handling in any language and
// would appreciate clarification on this matter.
//
// At this point, there's two sections with (ostensibly) the same information,
// and so any sane implementer just decides that having two sections is
// garbage and only implements .eh_frame, ignoring .debug_frame.  The good news
// is that that's what happened.  The bad news is that what is implemented is
// not exactly as the ABI describes.
//
// So what is actually *stored* there?  Think of what happens when we have an
// instruction stream like the following:
//
//    call 0x4095ef
//    next-insn ...
//
// That call can be thought of as two "micro"instructions: push the address of
// 'next-insn' onto the stack, and then jump to 0x4095ef.  This is important,
// because when the function at 0x4095ef is finished, the 'return' needs to
// do the reverse: pop off the address of 'next-insn' and jump to it.
//
// A debugger or profiler or exception handler needs this 'next-insn' address
// to be able to unwind the stack.  This is easy sometimes: if the instruction
// pointer is at 0x4095ef, for example, then we've just entered the function,
// and there a simple relation between the stack pointer (%rsp, nominally) and
// the address of 'next-insn'.  However, a debugger/profiler/EH handler needs
// to know where to return *at*all*times*.  It doesn't have the luxury of
// assuming the function has just been entered.
//
// This is a problem because of instructions such as:
//
//    push $42
//
// If the debugger previously knew that '%rsp-4' contained the return address,
// then after the execution of that push, the return address is now at
// '%rsp-8'---the push modified the stack pointer!
//
// The situation is compounded on x86-64, which eschews a frame pointer
// (%ebp's traditional role) in favor of an extra scratch register.
// However, some functions may choose to use %rbp "traditionally" (as a
// real frame pointer) anyway (gcc users can force the compiler to do this
// using "-fno-omit-frame-pointer", for example).
//
// The solution that the x86-64 ABI group decided on was to consider each
// function to be a series of regions and associate each region with a
// particular expression for computing the return address for that region.  For
// example, the expression for one section might be simply "*%rbp".  An
// algorithm for another section might be "%rsp - 64".
//
// The compiler is thus responsible for identifying each of these regions and
// recording the appropriate expression, which DWARF calls a "frame descriptor"
// or "FDE".  It must then store the list of these expressions, per-function,
// in a giant table contained within the .eh_frame section.
//
// To make things even more complicated, FDEs are contained inside "CIEs"
// ("c"ommon "i"nformation "e"ntries), and both FDEs and CIEs
// *share*the*same*header* and are *variable*length*.  So the algorithm is
// basically: read a bit, figure out if you're looking at a CIE or FDE, and
// then parse the rest. Even when you know what type it is, due to DWARF's
// "leb128" nonsense parsing must *still* deal with variable lengths.
//
// Unfortunately, in the "move" from one specification group to another, a lot
// of details seem to have changed.  For example, the DWARF3 spec says that a
// "CIE_id" version field is 32bits on 32-bit architectures, and 96bits (not a
// typo) on 64-bit architectures.  Yet in all binaries I've seen, the value is
// 32bits.  GDB has a specific test for the 64-bit indicator that bails out
// early with a comment of 'this is not supported'.  Yet it's quite clear that
// gdb works on 64-bit binaries.
//
// In short, the only way you could possibly understand this crap is if you
// grok somebody's source code that already understands this crap.  Due to
// inconsistencies among the ABI, DWARF, and cold, hard truth, don't trust
// anything less: if it never ran against real binaries, it doesn't work.
// Be careful when searching for help, too: x86 has a guaranteed frame pointer,
// and so all of this is complete nonsense for 32-bit x86.
package main

import(
  "debug/elf"
  "flag"
  "fmt"
  "log"
  "os"
	"../../ehframe"
)

var fname string
func init() {
  flag.StringVar(&fname, "f", "", "which file to examine")
}

func main() {
  flag.Parse()
  legolas, err := elf.Open(fname)
  if err != nil {
    fmt.Fprintf(os.Stderr, "could not open '%s': %s\n", fname, err)
    return
  }
  defer legolas.Close()

  frame := legolas.Section(".eh_frame")
  CFIs, err := section(fname, frame.Offset, frame.Size)
  if err != nil {
    log.Fatalf("could not read .eh_frame: %v\n", err)
    return
  }

  {
    rdr := ehframe.Start(CFIs)
    i := 0
    for cie, err := rdr.Next(); err == nil; cie, err = rdr.Next() {
      switch entry := cie.(type) {
      case ehframe.FDE:
        fmt.Printf("%2d FDE length=%d, CIElen=%d", i, entry.Length(),
                   entry.Associated.Length())
        if entry.Associated.Application == ehframe.Relative {
          beg := relative(entry.Offset[0], frame.Offset, 0x400000)
          end := relative(entry.Offset[1], frame.Offset, 0x400000)
          fmt.Printf(", Range: 0x%08x--0x%08x", beg, end)
        }
        // You may notice that all programs are an odd number of bytes.  That's
        // because they are padded by a bunch of 1-byte NOPs, so that the next
        // CIE or FDE is aligned (to 8 bytes, AFAICT).
        fmt.Printf("\n\tProgram (%d bytes):\n", len(entry.Program))

        program := entry.Program
        offset := uint(0)
        //dal := int(entry.Associated.DataAlign)
        //cal := int(entry.Associated.CodeAlign)
        for offset < uint(len(program)) && program[offset] != 0x0 {
          ixn := ehframe.Decode(program[offset:])
          fmt.Printf("\t\t%v\n", ixn)
          offset += ixn.Len
        }
        fmt.Println("")
      case ehframe.CIE:
        fmt.Printf("%2d CIE length=%d\n", i, entry.Length())
        fmt.Printf("\tAugmentation:   %30s\n", entry.Augmentation)
        fmt.Printf("\tCode alignment: %30d\n", entry.CodeAlign)
        fmt.Printf("\tData alignment: %30d\n", entry.DataAlign)
        fmt.Printf("\tRetAddr reg:    %30d\n", entry.RetAddrReg)
        fmt.Printf("\tAugment Len:    %30d\n", entry.AugmentationLen)
        fmt.Printf("\tFDE Encoding:   %15v, %15v\n", entry.Format,
                   entry.Application)
        fmt.Printf("\tProgram:\n")
        program := entry.Program
        offset := uint(0)
        //dal := entry.DataAlign
        //cal := entry.CodeAlign
        for offset < uint(len(program)) && program[offset] != 0x0 {
          ixn := ehframe.Decode(program[offset:])
          fmt.Printf("\t\t%v\n", ixn)
          offset += ixn.Len
        }
        fmt.Printf("\n")
      }
      i++
    }
  }
}

// reads the given section and returns it as a byte array.
func section(filename string, offset uint64, len uint64) ([]byte, error) {
  fp, err := os.Open(filename)
  if err != nil {
    return nil, err
  }
  defer fp.Close()

  rv := make([]byte, len)
  n, err := fp.ReadAt(rv, int64(offset))
  if err != nil {
    return nil, err
  }
  if n != int(len) {
    return nil, fmt.Errorf("read too short? %d bytes instead of %d", n, len)
  }

  return rv, nil
}

// 'Relative' means relative to the FDE itself.  We need to take into account
// the load address of the whole ELF object (load address of programs if it is
// a program; base address of the shared lib in memory if it's a library); the
// offset of ".ehframe" ELF section within the whole ELF header;
// the offset of *this* FDE within the table of all FDEs; and finally of course
// the LEB/value/address that was stored within the FDE itself.  This function
// assumes that the FDE's offset was already added into 'value'.
func relative(value uintptr, ehframe_off uint64, loadaddr uintptr) uintptr {
  return uintptr(int64(value) + int64(ehframe_off) + int64(loadaddr))
}
