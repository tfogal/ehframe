package ehframe
import(
  "bytes"
  "encoding/binary"
  "log"
)

func assembleu16(b []byte) uint16 {
  if len(b) != 2 {
    log.Fatalf("invalid length %d\n", len(b))
    return 0
  }
  var v uint16
  buf := bytes.NewReader(b)
  err := binary.Read(buf, binary.LittleEndian, &v)
  if err != nil {
    log.Fatalf("converting bytes: %v\n", err)
    return 0
  }
  return v
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

func assembles16(b []byte) int16 {
  if len(b) != 2 {
    log.Fatalf("invalid length %d\n", len(b))
    return 0
  }
  var v int16
  buf := bytes.NewReader(b)
  err := binary.Read(buf, binary.LittleEndian, &v)
  if err != nil {
    log.Fatalf("converting bytes: %v\n", err)
    return 0
  }
  return v
}
func assembles32(b []byte) int32 {
  if len(b) != 4 {
    log.Fatalf("invalid length %d\n", len(b))
    return 0
  }
  var v int32
  buf := bytes.NewReader(b)
  err := binary.Read(buf, binary.LittleEndian, &v)
  if err != nil {
    log.Fatalf("converting bytes: %v\n", err)
    return 0
  }
  return v
}
func assembles64(b []byte) int64 {
  if len(b) != 8 {
    log.Fatalf("invalid length %d\n", len(b))
    return 0
  }
  var v int64
  buf := bytes.NewReader(b)
  err := binary.Read(buf, binary.LittleEndian, &v)
  if err != nil {
    log.Fatalf("converting bytes: %v\n", err)
    return 0
  }
  return v
}
