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
// This EH information is *always* present: the author's guess is that the
// information is needed even if an exception can be thrown *through* a
// function.  Sooo.... basically all functions.  Even ones that aren't C++
// functions.  Yeeeep.
//
// At this point, there's two sections with (ostensibly) the same information,
// and so any sane implementor just decides that the DWARF or the ABI or
// whatever crap is complete bullshit and only implements .eh_frame, completely
// ignoring .debug_frame.  The good news is that that's what happened.  The bad
// news is that what is implemented is not exactly as the ABI describes.
//
// So what is actually *stored* there?  Think of what happens when the
// processor executes something like this:
//
//    call 0x4095ef
//    next-insn ...
//
// That call can be thought of as two "micro"instructions: push the address of
// 'next-insn' onto the stack, and then jump to 0x4095ef.  This is important,
// because when the function at 0x4095ef is finished, it needs to do the
// reverse: pop off the address of 'next-insn' and jump to it.
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
// grok somebody's source code that already reads this crap.  Due to
// inconsistencies among the ABI, DWARF, and cold, hard truth, don't trust
// anything less: if it never ran against real binaries, it doesn't work.
// Be careful when searching for help, too: x86 has a guaranteed frame pointer,
// and so all of this is complete nonsense for 32-bit x86.
package main

import(
  "debug/elf"
  "flag"
  "fmt"
  "io"
  "log"
  "os"
  "runtime"
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
    rdr := Start(CFIs)
    i := 0
    for cie, err := rdr.Next(); err == nil; cie, err = rdr.Next() {
      if cie.FDEp() {
        fde := FDE(*cie)
        assert(fde.id() != 0)
        fmt.Printf("%2d FDE length=%d, CIE=%d", i, fde.length(), rdr.CIE(fde))
        // use a new reader so we don't mess up our iteration.
        reader := Start(CFIs)
        reader.Seek(rdr.CIE(fde))
        assoc, err := reader.Next()
        if err != nil {
          log.Fatalf("bad index %d for associated CIE! %v", rdr.CIE(fde), err)
        }
        if assoc.Application() == Relative {
          // the +8 is because the addresses are relative to the start of the
          // *FDE*, and there are 8 bytes (4-byte length + 4-byte "CIE ID") at
          // the start of every record that do not count as the FDE.
          beg := relative(fde.begin(*assoc), rdr.prev_offset()+8, frame.Offset,
                          0x400000)
          end := relative(fde.end(*assoc), rdr.prev_offset()+8, frame.Offset,
                          0x400000)
          fmt.Printf(", Range: 0x%08x--0x%08x", beg, end)
        }
        fmt.Printf("\n\tProgram:\n")
        program := fde.program(*assoc)
        offset := uint(0)
        dal := assoc.data_alignment()
        cal := assoc.code_alignment()
        for offset < uint(len(program)) && program[offset] != 0x0 {
          ixn := Decode(program[offset:], cal, dal)
          fmt.Printf("\t\t%v\n", ixn)
          offset += ixn.Len
        }
        fmt.Println("")
      } else {
        fmt.Printf("%2d CIE length=%d\n", i, cie.length())
        fmt.Printf("\tVersion:        %30d\n", cie.version())
        fmt.Printf("\tAugmentation:   %30s\n", cie.augmentation())
        fmt.Printf("\tCode alignment: %30d\n", cie.code_alignment())
        fmt.Printf("\tData alignment: %30d\n", cie.data_alignment())
        fmt.Printf("\tRetAddr reg:    %30d\n", cie.retaddr_reg())
        fmt.Printf("\tAugment Len:    %30d\n", cie.augmentation_len())
        fmt.Printf("\tFDE Encoding:   %15v, %15v (0x%x)\n", cie.Format(),
                   cie.Application(), cie.fde_encoding())
        fmt.Printf("\tProgram:\n")
        program := cie.program()
        offset := uint(0)
        dal := cie.data_alignment()
        cal := cie.code_alignment()
        for offset < uint(len(program)) && program[offset] != 0x0 {
          ixn := Decode(program[offset:], cal, dal)
          fmt.Printf("\t\t%v\n", ixn)
          offset += ixn.Len
        }
        fmt.Printf("\n")
      }
      i++
    }
  }
}

// the 'Relative' FDE application is relative to the FDE itself.
func relative(value int64, fde_off uint64, ehframe_off uint64,
              loadaddr uintptr) uintptr {
  return uintptr(value + int64(fde_off) + int64(ehframe_off) + int64(loadaddr))
}

func readhdr(fname string) {
  legolas, err := elf.Open(fname)
  if err != nil {
    fmt.Fprintf(os.Stderr, "could not open '%s': %s\n", fname, err)
    return
  }
  defer legolas.Close()

  framehdr := legolas.Section(".eh_frame_hdr")
  fhdr, err := section(fname, framehdr.Offset, framehdr.Size)
  if err != nil {
    log.Fatalf("could not read .eh_frame_hdr: %v\n", err)
    return
  }
  fmt.Printf("fhdr version: %d\n", fhdr[0])
  fmt.Printf("fhdr encoding format: %v, %v\n", FDEApplication(fhdr[1] & 0xf0),
             FDEFormat(fhdr[1] & 0x0f))
  fmt.Printf("fhdr FDE encoding format: %s, %s\n",
             FDEApplication(fhdr[2] & 0xf0), FDEFormat(fhdr[2] & 0x0f))
  var fptr uint64
  switch(FDEApplication(fhdr[1] & 0xf0)) {
  case Absolute: fptr = uint64(assembleu32(fhdr[3:3+4]))
  // this makes no sense.  what's the current PC?
  case Relative: fptr = uint64(assembleu32(fhdr[3:3+4]))
  case DataRel: fptr = uint64(assembleu32(fhdr[3:3+4])) + framehdr.Offset
  case OmitApplication: fptr = 0x0
  }
  fmt.Printf("start of .eh_frame: %d (0x%x)\n", fptr, fptr)
}

// A Reader is used for iterating through the CIEs present in the binary.  Each
// call to 'Next()' gives back a new CIE.
type Reader struct {
  b []byte // data that holds the CIE information
  idx uint // current idx / where we are in the iteration space
  indices []uint // byte offset of each element.
  associated []uint // for each FDE, which CIE (idx) it is associated with.
}

// internal.  builds the internal 'indices' table we use for seeking around.
func (r *Reader) build_index_table() {
  r.indices = make([]uint, 0)
  offset := uint(0)
  for {
    cie := CIE(r.b[offset:])
    if cie.length() == 0 {
      break
    }
    r.indices = append(r.indices, offset) 
    // the length does not include the length of length of the length.
    offset += cie.length() + 4
  }
}

// Creates an iterator for running through CIE elements.
func Start(data []byte) *Reader {
  r := &Reader{b: data, idx: 0}
  r.build_index_table()
  r.Seek(0)
  return r
}
func (r *Reader) Seek(idx uint) error {
  if idx >= uint(len(r.indices)) {
    return fmt.Errorf("no index %d in %d-element list.", idx, len(r.indices))
  }
  r.idx = idx
  return nil
}
func (r *Reader) Next() (*CIE, error) {
  if r.idx >= uint(len(r.indices)) {
    return nil, io.EOF
  }
  cie_offset := r.indices[r.idx]
  r.idx++
  cie := (CIE)(r.b[cie_offset:])
  return &cie, nil
}
// returns the (byte) offset of the last CIE that Next() gave.
func (r *Reader) prev_offset() uint64 {
  assert(r.idx > 0)
  return uint64(r.indices[r.idx-1])
}
// Returns the associated index of the CIE for a given FDE.  The caller could
// then read that CIE by Seek()ing to it.
func (rdr *Reader) CIE(fde FDE) uint {
  // subtract 1: Next() will have incremented it, and they must have called
  // Next() before we got here, or they wouldn't have the FDE to give us as an
  // argument.
  offs := rdr.indices[rdr.idx-1] + 4 - uint(fde.id())
  assert(offs >= 0) // probably calculated rdr.indices wrong?

  // now we know what offset our CIE is at.  But we want to correlate that
  // offset to an index; the user shouldn't know such offsets exist.
  for k, v := range rdr.indices {
    if v == uint(offs) {
      return uint(k)
    }
  }
  return uint(offs)
}

func assert(cond bool) {
  if !cond {
    _, fname, line, ok := runtime.Caller(1)
    if ok {
      log.Fatalf("assertion %s:%d failed\n", fname, line)
    }
    log.Fatalf("failed assertion\n")
  }
}

// which algorithm to use for computing the address from the encoded values
type FDEApplication byte
const(
  Absolute FDEApplication = 0x00 // raw address.
  Relative FDEApplication = 0x10 // relative to current instruction ptr
  TextRel FDEApplication = 0x20 // relative to .text; not in standards.
  DataRel FDEApplication = 0x30 // relative to start of .eh_frame_hdr
  FuncRel FDEApplication = 0x40 // relative to ...?; not in standards.
  Indirect FDEApplication = 0x80 // indirect?  not in standards.
  OmitApplication FDEApplication = 0xf0 // not present.
)
func (app FDEApplication) String() string {
  switch(app) {
  case Absolute: return "Absolute"
  case Relative: return "Relative"
  case DataRel: return "Data relative"
  case OmitApplication: return "Omitted"
  }
  panic("invalid encoding for 'application'")
}

// methods for the encoding of values
type FDEFormat uint
const(
  OmitFormat FDEFormat = 0x0f
  ULEB128 FDEFormat = 0x01 // DWARF's "uleb128" abomination
  UData2 FDEFormat = 0x02 // uint16
  UData4 FDEFormat = 0x03 // uint32
  UData8 FDEFormat = 0x04 // uint64
  SLEB128 FDEFormat = 0x09 // DWARF's "sleb128" abomination
  SData2 FDEFormat = 0x0a // int16
  SData4 FDEFormat = 0x0b // int32
  SData8 FDEFormat = 0x0c // int64
)
func (format FDEFormat) String() string {
  switch(format) {
  case OmitFormat: return "omitted"
  case ULEB128: return "uleb128"
  case UData2: return "uint16"
  case UData4: return "uint32"
  case UData8: return "uint64"
  case SLEB128: return "sleb128"
  case SData2: return "int16"
  case SData4: return "int32"
  case SData8: return "int64"
  }
  panic("invalid encoding for 'format'")
}

const(
  id_cie = 0
)

// DWARF describes CFIs (call frame information) as being of two
// types: CIEs and FDEs.  There is a 1-1 mapping between CIEs and
// functions.  There is potentially-empty ordered sequence of FDEs per
// function.

// returns 1) the number of entries in the table, 2) how many of those entries
// are CIEs.  All entries that are not CIEs are FDEs.
func n_cfi_entries(b []byte) (uint, uint) {
  entries := uint(0)
  cies := uint(0)
  idx := uint(0)
  for {
    entries++
    len := assembleu32(b[idx:idx+4])
    idx += 4
    if len == 0xffffffff {
      // No tool can create such frame info.  How did we get here?
      panic("64bit .eh_frame information is not supported.  By anything.")
    } else if len == 0 { // sentinel.
      break
    }
    id := assembleu32(b[idx:idx+4])
    if id_cie == id {
      cies++
    }
    idx += uint(len)
  }
  return entries, cies
}

type CIE []byte
func (cie *CIE) length() uint {
  b := ([]byte)(*cie)
  len := assembleu32(b[0:4])
  // I know of no tooling that can create such a length.  Probably a parse err.
  if len == 0xffffffff {
    panic("64bit .eh_frame information is not supported.  By anything.")
  }
  // This should be unsigned.  But it should also not be ridiculously huge: 4
  // billion bytes would be a pretty large function.
  // This can sometimes catch offsets getting messed up / using the wrong base
  // address for the byte array of the CIE.  But a malicious user could force
  // us to crash by crafting an invalid object file, so might want to remove
  // eventually...
  assert((len & 0x80000000) == 0)
  return uint(len)
}

func (cie *CIE) id() uint {
  b := ([]byte)(*cie)
  id := assembleu32(b[4:8])
  return uint(id)
}

// true if this CIE is-an FDE.
func (cie *CIE) FDEp() bool {
  if cie.id() != 0 {
    return true
  }
  return false
}

func (cie *CIE) version() uint {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }
  b := ([]byte)(*cie)
  vers := b[8]
  // only versions 1, 3, and 4 are defined.  I have no idea what happened to 2.
  if vers < 1 || vers > 4 || vers == 2 {
    log.Fatalf("invalid version: %d\n", uint(vers))
  }
  return uint(vers)
}

func (cie *CIE) augmentation() string {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)
  // augmentation starts 9 bytes in.  it's a null-terminated string.. the
  // question is, where's the null?
  null := 9
  for {
    if b[null] == 0 {
      break
    }
    null++
  }
  aug := string(b[9:null+0])
  if len(aug) < 1 {
    log.Fatalf("invalid null 'augmentation' string.  not valid ELF?")
  }
  // old versions of gcc (before 3.0) used "eh" for the augmentation string.
  // The rest then (of course) had a different format.
  // We don't care about such old code: just recompile it.
  if len(aug) > 1 && aug[0] == 'e' && aug[1] == 'h' {
    panic("EH frame generated by gcc < 3.0; recompile with newer compiler.")
  }
  return aug
}

func (cie *CIE) code_alignment() uint {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)
  // what offset does this start at?  it's hard to say: the augmentation string
  // that comes before it is arbitrary-length.  But we know the aug string
  // started at 9...
  offset := 9 + len(cie.augmentation()) + 1

  // the 16 here is somewhat arbitrary: the max length of a leb128 is (of
  // course) 16 bytes.  but the whole purpose of LEBs is that they are normally
  // much shorter.  'nbytes' will tell us how long it actually was.
  leb, _ := uleb128(b[offset:offset+16])

  return uint(leb)
}

func (cie *CIE) data_alignment() int64 {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)
  // Again, we need to know the offset, but there are variably-sized fields.
  offset := uint(9 + len(cie.augmentation())) + 1
  _, nbytes := uleb128(b[offset:offset+16])
  offset += nbytes

  leb, _ := sleb128(b[offset:offset+16])
  return int64(leb)
}

func (cie *CIE) retaddr_reg() uint {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)
  // Again, we need to know the offset, but there are variably-sized fields.
  offset := uint(9 + len(cie.augmentation())) + 1
  _, nbytes := uleb128(b[offset:offset+16])
  offset += nbytes

  _, nbytes = sleb128(b[offset:offset+16])
  offset += nbytes

  // the format of the return address register is different in CIEs version 1
  // and 3.  Implicitly: I guess version's 2 and 4 do not have this field?
  if cie.version() == 1 {
    // in version 1, this is just a simple, easy byte.
    return uint(b[offset])
  } else if cie.version() == 3 {
    // in version 3, I guess we started worrying about architectures with > 256
    // registers.  it's a uleb128, now.
    leb, _ := uleb128(b[offset:offset+16])
    return uint(leb)
  }
  log.Fatalf("unknown CIE version: %d\n", cie.version())
  return 0xffffffff
}

func (cie *CIE) augmentation_len() uint64 {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)

  // there are a ton of variable-length LEBs before our augmentation data.
  offset := uint(9 + len(cie.augmentation())) + 1
  _, nbytes := uleb128(b[offset:offset+16]) // code alignment
  offset += nbytes
  _, nbytes = sleb128(b[offset:offset+16]) // data alignment
  offset += nbytes

  // this is fun.  in v1, the return address register was encoded in a single
  // byte.  v3 used a LEB.  le sigh.
  if cie.version() == 1 {
    offset++
  } else if cie.version() == 3 {
    _, nbytes = uleb128(b[offset:offset+16])
    offset += nbytes
  } else {
    panic("unknown version.  how big is the return address register?")
  }

  if cie.augmentation()[0] != 'z' {
    panic("augmentation does not start with 'z'.  No length.  Very senseless.")
  }
  alen, _ := uleb128(b[offset:offset+16])
  return alen
}

// returns the 'encoding' byte.  Internal use only!  Users should query
// 'Application' and 'Format'.
func (cie *CIE) fde_encoding() byte {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)

  offset := uint(9 + len(cie.augmentation())) + 1
  { // internal LEBs for 'alignment'.
    _, nbytes := uleb128(b[offset:offset+16]) // code alignment
    offset += nbytes
    _, nbytes = sleb128(b[offset:offset+16]) // data alignment
    offset += nbytes
  }

  // this is fun.  in v1, the return address register was encoded in a single
  // byte.  v3 used a LEB.  le sigh.
  if cie.version() == 1 {
    offset++
  } else if cie.version() == 3 {
    _, nbytes := uleb128(b[offset:offset+16])
    offset += nbytes
  } else {
    panic("unknown version.  how big is the return address register?")
  }

  if cie.augmentation()[0] != 'z' {
    panic("augmentation does not start with 'z'.  No length.  Very senseless.")
  }

  // the 'R' indicates our FDE encoding.  But we still need to watch for the
  // other bytes: we need to skip the other fields.
  aug := cie.augmentation()
  for i := 0; i < len(aug); i++ {
    ch := aug[i]
    switch(ch) {
    case 'z': { // length of aug data.  skip it.
      _, nbytes := uleb128(b[offset:offset+16])
      offset += nbytes
    }
    case 'L':
      offset += 1
    case 'R':
      return b[offset]
    case 'P':
      offset += 1
    case 'S':
      // signal handler.  Supposedly this is just a boolean flag, so we can
      // probably just get away with a no-op.  But I've never seen this in
      // practice and would rather be notified than potentially-silently give
      // bad data.
      // Note this does not exist in any standard docs.
      panic("signal handler case is unaccounted for")
    }
  }
  // "0xff" is the 'this was not present' encoding.
  return 0xff
}

// Every CIE and FDE contains a program in DWARF's virtual machine.  This
// returns the program's bytestream.
func (cie *CIE) program() []byte {
  if cie.id() != 0 {
    log.Fatalf("this is not a CIE: id 0x%x\n", cie.id())
  }

  b := ([]byte)(*cie)

  offset := uint(9 + len(cie.augmentation())) + 1
  { // internal LEBs for 'alignment'.
    _, nbytes := uleb128(b[offset:offset+16]) // code alignment
    offset += nbytes
    _, nbytes = sleb128(b[offset:offset+16]) // data alignment
    offset += nbytes
  }

  // this is fun.  in v1, the return address register was encoded in a single
  // byte.  v3 used a LEB.  le sigh.
  if cie.version() == 1 {
    offset++
  } else if cie.version() == 3 {
    _, nbytes := uleb128(b[offset:offset+16])
    offset += nbytes
  } else {
    panic("unknown version.  how big is the return address register?")
  }

  if cie.augmentation()[0] != 'z' {
    panic("augmentation does not start with 'z'.  No length.  Very senseless.")
  }

  // the 'R' indicates our FDE encoding.  But we still need to watch for the
  // other bytes: we need to skip the other fields.
  aug := cie.augmentation()
  for i := 0; i < len(aug); i++ {
    ch := aug[i]
    switch(ch) {
    case 'z': { // length of aug data.  skip it.
      _, nbytes := uleb128(b[offset:offset+16])
      offset += nbytes
    }
    case 'L': fallthrough
    case 'R': fallthrough
    case 'P': offset += 1
    case 'S':
      // signal handler.  Supposedly this is just a boolean flag, so we can
      // probably just get away with a no-op.  But I've never seen this in
      // practice and would rather be notified than potentially-silently give
      // bad data.
      // Note this does not exist in any standard docs.
      panic("signal handler case is unaccounted for")
    }
  }

  // the +4 is because the length does not include itself.
  return b[offset:cie.length()+4]
}

// Every CIE and FDE contains a program in DWARF's virtual machine.  This
// returns the program's bytestream.
func (fde *FDE) program(cie CIE) []byte {
  assert(fde.id() != 0)

  offset := int(4 + 4) // sizeof(length) + sizeof(id)

  b := ([]byte)(*fde)

  switch(cie.Format()) {
  case OmitFormat: panic("impossible")
  case ULEB128:
    _, nb := uleb128(b[offset:offset+16])
    offset += int(nb)
    _, nb = uleb128(b[offset:offset+16])
    offset += int(nb)
  case SLEB128:
    _, nb := sleb128(b[offset:offset+16])
    offset += int(nb)
    _, nb = sleb128(b[offset:offset+16])
    offset += int(nb)
  case UData2: fallthrough
  case SData2: offset += 2*2
  case UData4: fallthrough
  case SData4: offset += 2*4
  case UData8: fallthrough
  case SData8: offset += 2*8
  }

  if cie.augmentation()[0] == 'z' {
    end := offset+16
    if int(fde.length()) < end {
      end = int(fde.length())
    }
    _, nbytes := uleb128(b[offset:end])
    offset += int(nbytes)
  }
  //log.Print("If the LSDA is not omitted, then there is an LSDA pointer " +
  //          "here that we are not accounting for!")
  // +4: the length does not include itself.
  return b[offset:fde.length()+4]
}

// returns the FDE "application": how the FDE values should be applied.
func (cie *CIE) Application() FDEApplication {
  encoding := cie.fde_encoding()
  if 0xff == encoding { // defaults to 'absolute'.
    return Absolute
  }
  return FDEApplication(encoding & 0xf0)
}

// returns the FDE "format": how the addresses are encoded in the stream.
func (cie *CIE) Format() FDEFormat {
  encoding := cie.fde_encoding()
  return FDEFormat(encoding & 0x0f)
}


type FDE []byte
// returns the length of the FDE.
func (fde *FDE) length() uint {
  as_cie := CIE(*fde)
  return as_cie.length()
}

// returns the FDE's ID, which is the byte offset to its associated CIE.
func (fde *FDE) id() uint {
  // this is shared with the CIE, but the FDE's ID is interpreted as a signed
  // offset.
  as_cie := CIE(*fde)
  return as_cie.id()
}

// returns the starting address that this FDE applies to.  Note that this does
// not have the 'algorithm' applied to it.  The appropriate algorithm is almost
// always 'Relative'.  In that case, you need to add in:
//    the offset the ELF image was loaded at (0x400000 if this is not in mem)
//    the offset of the .eh_frame section within the ELF image
//    the offset within .eh_frame to the start of this FDE
func (fde *FDE) begin(cie CIE) int64 {
  offset := int(4 + 4) // sizeof(length) + sizeof(id)

  b := ([]byte)(*fde)

  // How is that stored in the object?  The CIE knows.
  switch(cie.Format()) {
  case OmitFormat:
    panic("this case is impossible; format should default to absolute")
  case ULEB128: v, _ := uleb128(b[offset:offset+16]); return int64(v)
  case UData2: return int64(assembleu16(b[offset:offset+2]))
  case UData4: return int64(assembleu32(b[offset:offset+4]))
  case UData8: return int64(assembleu64(b[offset:offset+8]))
  case SLEB128: v, _ := sleb128(b[offset:offset+16]); return int64(v)
  case SData2: return int64(assembles16(b[offset:offset+2]))
  case SData4: return int64(assembles32(b[offset:offset+4]))
    //return uintptr(0x400000 - assembles32(b[offset:offset+4]))
  case SData8: return int64(assembles64(b[offset:offset+8]))
  }
  panic("unreachable")
  return 0x0
}

func (fde *FDE) end(cie CIE) int64 {
  offset := int(4 + 4) // sizeof(length) + sizeof(id)

  b := ([]byte)(*fde)

  addr := fde.begin(cie)

  // The start address and length come next.  We already read the start address
  // ('addr') and now need the length, then we'll just add them together.
  // Unfortunately, we can't just statically compute a byte offset for the
  // length: since they the start address could be a LEB, we don't know how
  // long it is without actually parsing it.
  // Note that in the signed cases we assert that we get back a non-negative
  // value.  It does not make sense for the length to be negative.  We *should*
  // do proper error handling, but in practice the only time we'll hit the case
  // is if we have a coding bug or we hit a maliciously-created file.  We
  // decide that we don't care about the latter and just assert it.
  switch(cie.Format()) {
  case OmitFormat:
    panic("impossible")
  case ULEB128:
    _, nb := uleb128(b[offset:offset+16])
    offset += int(nb)
    length, nb := uleb128(b[offset:offset+16])
    return addr+int64(length)
  case UData2:
    offset += 2
    length := assembleu16(b[offset:offset+2])
    return addr+int64(length)
  case UData4:
    offset += 4
    length := assembleu32(b[offset:offset+4])
    return addr+int64(length)
  case UData8:
    offset += 8
    length := assembleu64(b[offset:offset+8])
    return addr+int64(length)
  case SLEB128:
    _, nb := sleb128(b[offset:offset+16])
    offset += int(nb)
    length, nb := sleb128(b[offset:offset+16])
    assert(length >= 0)
    return addr+int64(length)
  case SData2:
    offset += 2
    length := assembles16(b[offset:offset+2])
    assert(length >= 0)
    return addr+int64(length)
  case SData4:
    offset += 4
    length := assembles32(b[offset:offset+4])
    assert(length >= 0)
    return addr+int64(length)
  case SData8:
    offset += 8
    length := assembles64(b[offset:offset+8])
    assert(length >= 0)
    return addr+length
  }
  panic("unreachable")
  return 0x0
}

// gives back a byte array of the given section of a file.
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
