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
  "errors"
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
      switch entry := cie.(type) {
      case FDE:
        fmt.Printf("%2d FDE length=%d, CIElen=%d", i, entry.Length(),
                   entry.Associated.Length())
        if entry.Associated.Application == Relative {
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
        dal := int(entry.Associated.DataAlign)
        cal := int(entry.Associated.CodeAlign)
        for offset < uint(len(program)) && program[offset] != 0x0 {
          ixn := Decode(program[offset:], cal, dal)
          fmt.Printf("\t\t%v\n", ixn)
          offset += ixn.Len
        }
        fmt.Println("")
      case CIE:
        fmt.Printf("%2d CIE length=%d\n", i, entry.Length())
        fmt.Printf("\tAugmentation:   %30s\n", entry.Augmentation)
        fmt.Printf("\tCode alignment: %30d\n", entry.CodeAlign)
        fmt.Printf("\tData alignment: %30d\n", entry.DataAlign)
        fmt.Printf("\tRetAddr reg:    %30d\n", entry.RetAddrReg)
        fmt.Printf("\tAugment Len:    %30d\n", entry.AugmentationLen)
        fmt.Printf("\tFDE Eentryoding:   %15v, %15v\n", entry.Format,
                   entry.Application)
        fmt.Printf("\tProgram:\n")
        program := entry.Program
        offset := uint(0)
        dal := entry.DataAlign
        cal := entry.CodeAlign
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
  associated []uint // for each FDE, which CIE (the idx) it is associated with.
}

// builds the internal 'indices' table we use for seeking around.
// 'indices[i]' gives the byte offset in 'b' that each CIE or FDE starts.
func (r *Reader) build_index_table() {
  r.indices = make([]uint, 0)
  offset := uint(0)
  for {
    length := assembleu32(r.b[offset:offset+4])
    if length == 0 {
      break
    }
    r.indices = append(r.indices, offset) 
    // +4: the length does not include the length of the length.
    offset += uint(length + 4)
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

// Next grabs the next CIE from the bytestream.
func (r *Reader) Next() (CommonInfo, error) {
  if r.idx >= uint(len(r.indices)) {
    return nil, io.EOF
  }
  cie_offset := r.indices[r.idx]
  r.idx++

  // The CIE or FDE starts at cie_offset.  However, we can't know whether it's
  // a CIE or an FDE until we've read the second uint from the stream.
  id := assembleu32(r.b[cie_offset+4:cie_offset+8])
  if id == 0 { // then it's a CIE.
    return parse_cie(r.b[cie_offset:])
  }

  // It's an FDE, but we can't parse the FDE without grokking the associated
  // CIE.  The byte offset from the FDE's start (defined as past the length and
  // ID fields) *is* this entry's 'id' field.
  offs := r.indices[r.idx-1] + 4 - uint(id)
  associated, err := parse_cie(r.b[offs:])
  // FDEs only reference CIEs that have already been seen.  And by definition,
  // those earlier CIEs parsed, or we would not have reached here.
  // So the only way that could've given us an error is if we computed 'offs'
  // incorrectly above, or some broken/malicious file wrote an invalid id.
  if err != nil {
    log.Fatalf("internal error: CIE should be valid: %v\n", err)
    return nil, err
  }
  return parse_fde(r.b[cie_offset:], associated, int64(cie_offset))
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

// DWARF describes CFIs (call frame information) as being of two
// types: CIEs and FDEs.  There is a 1-1 mapping between CIEs and
// functions.  There is a potentially-empty ordered sequence of FDEs per
// function.

type CommonInfo interface {
  Length() uint
  id() uint
}

type CIE struct {
  length uint
  Augmentation string
  CodeAlign int
  DataAlign int
  RetAddrReg uint
  AugmentationLen uint
  Format FDEFormat
  Application FDEApplication
  Program []byte
}

func (c CIE) Length() uint {
  return c.length
}
// A CIE ID is always 0; you cannot create one otherwise.
func (CIE) id() uint {
  return 0
}

type FDE struct {
  Offset [2]uintptr // byte range this FDE applies to
  Program []byte
  Associated CIE
  length uint
}

func (f FDE) Length() uint {
  return f.length
}
func (f FDE) id() uint {
  assert(false) // FIXME, implement
  return 42
}

var(
  ErrFDE = errors.New("record is an FDE, not a CIE")
)

func parse_cie(cie []byte) (CIE, error) {
  length := assembleu32(cie[0:4])

  // I know of no tooling that can create such a length.  Probably a parse err.
  if length == 0xffffffff {
    panic("64bit .eh_frame information is not supported.  By anything.")
  }
  // The length should be unsigned.  But it should also not be ridiculously
  // huge: 4 billion bytes would be a pretty large function.
  // This can sometimes catch offsets getting messed up / using the wrong base
  // address for the byte array of the CIE.  But a malicious user could force
  // us to crash by crafting an invalid object file, so might want to remove
  // eventually...
  assert((length & 0x80000000) == 0)
  id := assembleu32(cie[4:8])

  if id != 0 {
    return CIE{}, ErrFDE
  }

  version := cie[8]
  if version < 1 || version > 4 || version == 2 {
    return CIE{}, fmt.Errorf("invalid version %d", version)
  }

  // augmentation starts 9 bytes in.  it's a null-terminated string... the
  // question is, where's the null?
  null := 9
  for {
    if cie[null] == 0 {
      break
    }
    null++
  }
  aug := string(cie[9:null+0])
  if len(aug) < 1 {
    return CIE{}, fmt.Errorf("invalid 'augmentation' string")
  }

  // the aug string started at 9, code alignment comes next
  offset := uint(9 + len(aug) + 1)
  // the 16 here is rather arbitrary: the max length of a leb128 is (of
  // course) 16 bytes.  but the whole purpose of LEBs is that they are normally
  // much shorter.  'nbytes' will tell us how long it actually was.
  code_align, nbytes := uleb128(cie[offset:offset+16])

  // old versions of gcc (before 3.0) used "eh" for the augmentation string.
  // We don't care about such old code: just recompile it.
  if len(aug) > 1 && aug[0] == 'e' && aug[1] == 'h' {
    return CIE{}, errors.New("old EH info; recompile target program")
  }

  offset += nbytes
  data_align, nb := sleb128(cie[offset:offset+16])

  offset += nb

  retaddr_reg := uint(0)
  // the format of the return address register is different in CIEs version 1
  // and 3.  Implicitly: I guess version's 2 and 4 do not have this field?
  if version == 1 {
    // in version 1, this is just a simple, easy byte.
    retaddr_reg = uint(cie[offset])
    offset++
  } else if version == 3 {
    // in version 3, I guess we started worrying about architectures with > 256
    // registers.  it's a uleb128, now.
    leb, nby := uleb128(cie[offset:offset+16])
    retaddr_reg = uint(leb)
    offset += nby
  }

  assert(aug[0] == 'z')
  auglen, nby := uleb128(cie[offset:offset+16])
  offset += nby

  fde_encoding := byte(0xff)
  for i := 1; i < len(aug); i++ {
    ch := aug[i]
    switch(ch) {
    case 'L': offset += 1
    case 'R':
      fde_encoding = cie[offset]
      offset += 1
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

  program := cie[offset:length+4]

  format := FDEFormat(fde_encoding & 0x0f)
  application := FDEApplication(fde_encoding & 0xf0)

  return CIE{length: uint(length), Augmentation: aug,
             CodeAlign: int(code_align), DataAlign: int(data_align),
             RetAddrReg: retaddr_reg, AugmentationLen: uint(auglen),
             Format: format, Application: application,
             Program: program}, nil
}

// parses an FDE from the given byte stream.
//  fde - byte stream to parse it out of
//  cie - the CIE that this FDE is associated with.
//  fde_offset - 'fde' is a subset of a large stream: this is the start offset
func parse_fde(fde []byte, cie CIE, fde_offset int64) (FDE, error) {
  length := assembleu32(fde[0:4])

  offset := uint(8) // the ID comes after len, but we don't need it.

  begin := int64(0)
  end := int64(0)

  // Next come the beginning address and the length.
  // Note that in the signed cases we assert that we get back a non-negative
  // value.  It does not make sense for the length to be negative.  We *should*
  // do proper error handling, but in practice the only time we'll hit the case
  // is if we have a coding bug or we hit a maliciously-created file.  We
  // decide that we don't care about the latter and just assert it.
  switch(cie.Format) {
  case OmitFormat:
    panic("this case is impossible; format should default to absolute")
  case ULEB128:
    v, nb := uleb128(fde[offset:offset+16])
    begin = int64(v)
    offset += nb
    v, nb = uleb128(fde[offset:offset+16])
    end = begin + int64(v)
    offset += nb
  case UData2:
    begin = int64(assembleu16(fde[offset:offset+2]))
    offset += 2
    end = begin + int64(assembleu16(fde[offset:offset+2]))
    offset += 2
  case UData4:
    begin = int64(assembleu32(fde[offset:offset+4]))
    offset += 4
    end = begin + int64(assembleu32(fde[offset:offset+4]))
    offset += 4
  case UData8:
    begin = int64(assembleu64(fde[offset:offset+8]))
    offset += 8
    end = begin + int64(assembleu64(fde[offset:offset+8]))
    offset += 8
  case SLEB128:
    v, nb := sleb128(fde[offset:offset+16])
    begin = int64(v)
    offset += nb
    v, nb = sleb128(fde[offset:offset+16])
    assert(v > 0)
    end = begin + int64(v)
    offset += nb
  case SData2:
    begin = int64(assembles16(fde[offset:offset+2]))
    offset += 2
    end = begin + int64(assembles16(fde[offset:offset+2]))
    assert(assembles16(fde[offset:offset+2]) > 0)
    offset += 2
  case SData4:
    begin = int64(assembles32(fde[offset:offset+4]))
    offset += 4
    end = begin + int64(assembles32(fde[offset:offset+4]))
    assert(assembles32(fde[offset:offset+4]) > 0)
    offset += 4
  case SData8:
    begin = int64(assembles64(fde[offset:offset+8]))
    offset += 8
    end = begin + int64(assembles64(fde[offset:offset+8]))
    assert(assembles64(fde[offset:offset+8]) > 0)
    offset += 8
  }

  // if so, we need to skip over its (variable-length) value.
  if cie.Augmentation[0] == 'z' {
    // unfortunately a simple offset:offset+16 could go beyond the end of the
    // array here, if we're not careful.  default to offset+16 but scale it
    // back if that's too ambitious.
    fdend := offset+16
    if uint(length) < fdend {
      fdend = uint(length)
    }
    _, nbytes := uleb128(fde[offset:fdend])
    offset += nbytes
  }

  //log.Print("If the LSDA is not omitted, then there is an LSDA pointer " +
  //          "here that we are not accounting for!")
  // +4: the length does not include itself.
  program := fde[offset:length+4]

  // The addresses given by 'begin' and 'end' are relative to the start of the
  // FDE we are currently parsing.  For the purposes of these address
  // calculations, the start of the FDE is past the common info that both CIEs
  // and FDEs share (length and IDs).
  begin += fde_offset + 8
  end += fde_offset + 8

  return FDE{Offset: [2]uintptr{uintptr(begin), uintptr(end)},
             Associated: cie, Program: program, length: uint(length)}, nil
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
