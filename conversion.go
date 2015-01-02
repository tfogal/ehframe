// LEB128 handling code.
// You'll need the DWARF spec and a stiff drink to make any sense of this.  The
// basic idea is to encode hex values (really, addresses, as they are used in
// DWARF) in fewer bytes by chopping off all the leading 0s.  Of course, it's
// completely ambiguous how wide an address is, then, and so the encoding sets
// the high bit to indicate 'done'.
//
// There are no functions to *create* LEB128s, only convert them to sane
// representations.  Proliferating LEB128s is the root of all evil.
package main
import "io"

func uleb128(leb []uint8) (uint64, uint) {
  accum := uint64(0)
  for i, b := range leb {
    accum |= uint64(b & 0x7f) << uint64(i*7)
    if b & 0x80 == 0 {
      return accum, uint(i)+1
    }
  }
  panic("uLEB has no sentinel?")
}

func sleb_step(value int64, by uint8, iter uint) (int64, error) {
  if by & 0x80 == 0 {
    v := int64(by & 0x7f)
    value |= v << (iter*7)
    return value, io.EOF
  }
  value |= int64(by & 0x7f) << (iter*7)
  return value, nil
}

func sleb128(leb []byte) (int64, uint) {
  accum := int64(0)
  for i, b := range leb {
    var done error
    accum, done = sleb_step(accum, b, uint(i))
    if done == io.EOF {
      i++
      if b & 0x40 != 0 { // sign extension.
        accum |= int64(-1) << uint64(7*i)
      }
      return accum, uint(i)
    }
  }
  panic("sLEB has no sentinel?")
}
