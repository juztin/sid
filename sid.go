// Package sid provides a way to parse Microsoft SID's from []byte to a string.
package sid

import (
	"fmt"
	"strings"
)

func part(b []byte) uint32 {
	// Convert 4 bytes to 32 bit little endian.
	return uint32(b[0]) +
		uint32(b[1])<<8 +
		uint32(b[2])<<16 +
		uint32(b[3])<<24
}

func ntAuthority(b []byte) uint64 {
	// Convert 6 bytes to 48 bit, 64 bit container, big endian.
	return uint64(b[5]) +
		uint64(b[4])<<8 +
		uint64(b[3])<<16 +
		uint64(b[2])<<24 +
		uint64(b[1])<<32 +
		uint64(b[0])<<40
}

// New returns a parsed SID. The given data must be in []byte{int} format.
// 		New([]byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 43, 52, 57, 115, 230, 121, 21, 81, 132, 12, 135, 9, 129, 22, 0, 0,})
func New(b []byte) (string, error) {
	if b == nil {
		return "", fmt.Errorf("nil []byte received")
	} else if len(b) < 13 {
		return "", fmt.Errorf("invalid length for []byte, need at-least 12")
	}
	revision := fmt.Sprintf("S-%d", b[0])
	ntAuthority := ntAuthority(b[2:8])
	ntNonUnique := part(b[8:12])
	dashes := int(b[1])
	// revision + dashes +
	expectedLen := 1 + 1 + 6 + (dashes * 4)
	if len(b) != expectedLen {
		return "", fmt.Errorf("invalid length for []byte, expected %d got %d", expectedLen, len(b))
	}

	var parts []string
	for i, j := 1, 12; i < dashes; i, j = i+1, j+4 {
		p := part(b[j : j+4])
		parts = append(parts, fmt.Sprintf("%d", p))
	}

	return fmt.Sprintf("%s-%d-%d-%s", revision, ntAuthority, ntNonUnique, strings.Join(parts, "-")), nil
}
