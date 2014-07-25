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
