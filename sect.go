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
  "bytes"
  "debug/elf"
  "encoding/binary"
  "flag"
  "fmt"
  "io"
  "log"
  "os"
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
        fmt.Printf("%2d FDE length=%d, CIE=%d\n", i, fde.length(), rdr.CIE(fde))
      } else {
        fmt.Printf("%2d CIE length=%d\n", i, cie.length())
        fmt.Printf("\tVersion:        %30d\n", cie.version())
        fmt.Printf("\tAugmentation:   %30s\n", cie.augmentation())
        fmt.Printf("\tCode alignment: %30d\n", cie.code_alignment())
        fmt.Printf("\tData alignment: %30d\n", cie.data_alignment())
        fmt.Printf("\tRetAddr reg:    %30d\n", cie.retaddr_reg())
        fmt.Printf("\tAugment Len:    %30d\n", cie.augmentation_len())
        //fmt.Printf("\tAug data: %31s 0x%02x\n", "", cie.aug_data())
      }
      i++
    }
  }

/*
  framehdr := legolas.Section(".eh_frame_hdr")
  fhdr, err := section(fname, framehdr.Offset, framehdr.Size)
  if err != nil {
    log.Fatalf("could not read .eh_frame_hdr: %v\n", err)
    return
  }
  fmt.Printf("fhdr version: %d\n", fhdr[0])
  fmt.Printf("fhdr encoding format: %s, %s\n", algorithm(fhdr[1]),
             encoding(encptr(fhdr[1] & 0x0f)))
  fmt.Printf("fhdr FDE encoding format: %s, %s\n", algorithm(fhdr[2]),
             encoding(encptr(fhdr[2] & 0x0f)))
  var fptr uint64
  switch(fhdr[1] & 0xf0) {
  case eh_absolute: fptr = uint64(assembleu32(fhdr[3:3+4]))
  // this makes no sense.  what's the current PC?
  case eh_relative: fptr = uint64(assembleu32(fhdr[3:3+4]))
  case eh_data_rel: fptr = uint64(assembleu32(fhdr[3:3+4])) + framehdr.Offset
  case eh_omit: fptr = 0x0
  }
  fmt.Printf("start of .eh_frame: %d (0x%x)\n", fptr, fptr)
*/
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

// Creates the iterator for running through CIE elements.
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
    panic("assertion failure")
  }
}

// which algorithm to use for computing the address from the encoded values
const(
  eh_absolute = 0x00 // raw address.
  eh_relative = 0x10 // relative to current instruction ptr
  eh_data_rel = 0x30 // relative to start of .eh_frame_hdr
  eh_omit = 0xff // not present.
)
func algorithm(alg byte) string {
  if alg == 0xff {
    return "not present"
  }
  switch(alg & 0xf0) { // algorithm is only in high nibble!
  case eh_absolute: return "absolute"
  case eh_relative: return "relative"
  case eh_data_rel: return "relative to .eh_frame_hdr start"
  }
  return "invalid algorithm"
}
// methods for the encoding of values
type encptr uint
const(
  // eh_omit = 0xff ; borrowed from the above table, since it's the same.
  eh_uleb128 encptr = 0x01 // DWARFs "uleb128" abomination
  eh_udata2 = 0x02 // uint16
  eh_udata4 = 0x03 // uint32
  eh_udata8 = 0x04 // uint64
  eh_sleb128 = 0x09 // DWARFs "sleb128" abomination
  eh_sdata2 = 0x0a // int16
  eh_sdata4 = 0x0b // int32
  eh_sdata8 = 0x0c // int64
)
func encoding(method encptr) string {
  if eh_omit == method {
    return "omitted"
  }
  switch(method & 0xf) { // method is only in low nibble!
  case eh_uleb128: return "uleb128"
  case eh_udata2: return "uint16"
  case eh_udata4: return "uint32"
  case eh_udata8: return "uint64"
  case eh_sleb128: return "sleb128"
  case eh_sdata2: return "int16"
  case eh_sdata4: return "int32"
  case eh_sdata8: return "int64"
  }
  return "invalid encoding"
}

func assembleu32(b []byte) uint32 {
  if len(b) != 4 {
    log.Fatalf("invalid length %d\n", len(b))
    return 0
  }
  var v uint32
  buf := bytes.NewReader(b)
  err := binary.Read(buf, binary.LittleEndian, &v)
  if err != nil {
    log.Fatalf("converting bytes: %v\n", err)
    return 0
  }
  return v
}
func assembleu64(b []byte) uint64 {
  if len(b) != 8 {
    log.Fatalf("invalid length %d\n", len(b))
    return 0
  }
  var v uint64
  buf := bytes.NewReader(b)
  err := binary.Read(buf, binary.LittleEndian, &v)
  if err != nil {
    log.Fatalf("converting bytes: %v\n", err)
    return 0
  }
  return v
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
  len := assembleu32(b[0:0+4])
  // I know of no tooling that can create such a length.  Probably a parse err.
  if len == 0xffffffff {
    panic("64bit .eh_frame information is not supported.  By anything.")
  }
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

/*
{
  auglen := uint64(0)
  for aug := range cie.augmentation() {
    switch(aug) {
    case 'z':
      alen, nb := uleb128(b[offset:offset+16])
      auglen = alen
      offset += nb
      fmt.Printf("length of augmentation opcodes (bytes): %d\n", auglen)
    case 'L':
      lsda := int(b[offset])
      offset++
      fmt.Printf("LSDA encoding: %d\n", lsda)
    case 'R':
      fdeenc := int(b[offset])
      offset++
      fmt.Printf("FDE encoding: %d\n", fdeenc)
    case 'P':
      // I honestly have no idea what this means.
      encoding := uint(b[offset])
      offset++
      v, nb := read_encoded(b, offset-1, encoding, uint64(offset-1) + auglen)
      offset += nb
    }
  }
}
*/

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
