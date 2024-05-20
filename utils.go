package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func Uint64ToMAC(value uint64) string {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, value)
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func BytesRepeat(b byte, n int) []byte {
	return bytes.Repeat([]byte{b}, n)
}

func Uint16ToBytes(value uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, value)
	return b
}

func Uint32ToBytes(value uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, value)
	return b
}

func Uint64ToBytes(value uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, value)
	return b
}

func Uint64ToBytesBe(value uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, value)
	return b
}

func BytesToUint16(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b)
}

func BytesToUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

func BytesToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}
