// Package bech32 implements BIP173.
package bech32

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// ChecksumError signals data corruption. A positive ChecksumError may be
// treated as warning, whereby the integer value represents the number of
// bits corrected.
type ChecksumError int

// Error implements the standard error interface.
func (e ChecksumError) Error() string {
	if e == 0 {
		return "bech32: data corruption; checksum recovery failed"
	}
	return fmt.Sprintf("bech32: data corruption; %d bits corrected", e)
}

// Dictionary is the lower-case character set for data encoding, in which the
// index of each character represents its respective numerical (5-bit) value.
const dictionary = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// CharTable reverses dictionary for parsing.
var charTable = [256]byte{
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	15, 99, 10, 17, 21, 20, 26, 30, 7, 5, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 29, 99, 24, 13, 25, 9, 8, 23, 99, 18, 22, 31, 27, 19, 99,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
}

// Protocol violations are rejected in a strict manner.
var (
	ErrBig       = errors.New("bech32: serial exceeds 90 characters")
	errCaseMix   = errors.New("bech32: mix of upper and lower-case not allowed")
	errNoLabel   = errors.New("bech32: human-readable part absent")
	errNoCksum   = errors.New("bech32: data part incomplete; need 6 character checksum")
	errLabelChar = errors.New("bech32: illegal character in human-readable part")
	errDataChar  = errors.New("bech32: illegal character in data part")
)

// Parse decodes a Bech32 string, with label for the human-readable part/prefix.
// Padding has the number of zero bits added to the last data byte, in the range
// of 0 to 7.
func Parse(s string) (label string, payload []byte, padding int, err error) {
	if len(s) > 90 {
		return "", nil, 0, ErrBig
	}

	if lower := strings.ToLower(s); lower != s {
		if strings.ToUpper(s) != s {
			return "", nil, 0, errCaseMix
		}
		s = lower // continue with lowercase
	}

	i := strings.LastIndexByte(s, '1')
	if i <= 0 {
		return "", nil, 0, errNoLabel
	} else if len(s)-i < 7 {
		return "", nil, 0, errNoCksum
	}

	label = s[:i]
	code, err := labelCheck(label)
	if err != nil {
		return "", nil, 0, err
	}

	i++ // data part offset
	checksumStart := len(s) - 6
	payload = make([]byte, ((((checksumStart - i) * 5) + 7) / 8))
	var o int // write index for payload

	var acc uint64 // accumulate buffer
	var accN uint  // accumulute count
	for ; i < checksumStart; i++ {
		v := charTable[s[i]]
		if v > 31 {
			return "", nil, 0, errDataChar
		}

		code = check5Bits(code, uint(v))

		acc = acc<<5 | uint64(v)
		accN += 5
		if accN == 40 {
			payload[o+0] = byte(acc >> 32)
			payload[o+1] = byte(acc >> 24)
			payload[o+2] = byte(acc >> 16)
			payload[o+3] = byte(acc >> 8)
			payload[o+4] = byte(acc >> 0)
			o += 5

			accN = 0 // clear
		}
	}
	// flush remaining bits
	for ; accN > 7; accN -= 8 {
		payload[o] = byte(acc >> (accN - 8))
		o++
	}
	if accN != 0 {
		padding = int(8 - accN)
		payload[o] = byte(acc << uint(padding))
	}

	// checksum
	for ; i < len(s); i++ {
		v := charTable[s[i]]
		if v > 31 {
			return "", nil, 0, errDataChar
		}
		code = check5Bits(code, uint(v))
	}
	if code != 1 {
		// BUG(pascaldekloe): Error recovery not implemented yet.
		// All data corruption leads to ChecksumError zero.
		return "", nil, 0, ChecksumError(0)
	}

	return label, payload, padding, nil
}

// Parse encodes a Bech32 string, with label for the human-readable part/prefix.
// A total of bitN bits are read from p in big endian (bit and byte) order. The
// result may contain up to four additional data bits, as it encodes in chunks
// of 5 bits. The padding bits are all zero.
func Format(label string, p []byte, bitN int) (string, error) {
	if bitN < 0 {
		bitN = 0
	}
	if len(p)*8 < bitN {
		return "", io.ErrShortBuffer
	}

	// label + '1' seperator + payload base32 + checksum base64
	l := 7 + len(label) + (bitN+4)/5
	if l > 90 {
		return "", ErrBig
	}
	var b strings.Builder
	b.Grow(l)
	b.WriteString(label)
	b.WriteByte('1')

	code, err := labelCheck(label)
	if err != nil {
		return "", err
	}

	var acc uint  // accumulate buffer
	var accN uint // accumulute count
	pendingN := uint(bitN)
	for _, c := range p {
		acc = acc<<8 | uint(c)
		if pendingN < 5 {
			accN += 8
			break
		}
		accN += 3
		if pendingN > 9 && accN > 4 {
			// do two base32 characters
			v := acc >> accN & 31
			accN -= 5
			code = check5Bits(code, v)
			b.WriteByte(dictionary[v])
			pendingN -= 5
		}
		v := acc >> accN & 31
		code = check5Bits(code, v)
		b.WriteByte(dictionary[v])
		pendingN -= 5
	}
	if pendingN != 0 {
		acc >>= accN - pendingN
		acc <<= 5 - pendingN
		code = check5Bits(code, acc)
		b.WriteByte(dictionary[acc])
	}

	// checksum
	for i := 0; i < 6; i++ {
		code = check5Bits(code, 0)
	}
	code ^= 1
	b.WriteByte(dictionary[code>>25&31])
	b.WriteByte(dictionary[code>>20&31])
	b.WriteByte(dictionary[code>>15&31])
	b.WriteByte(dictionary[code>>10&31])
	b.WriteByte(dictionary[code>>5&31])
	b.WriteByte(dictionary[code>>0&31])

	return b.String(), nil
}

// LabelCheck validates the label and returns the checksum.
func labelCheck(label string) (uint, error) {
	code := uint(1) // BCH checksum
	for i := 0; i < len(label); i++ {
		if label[i] < 33 || label[i] > 126 {
			return 0, errLabelChar
		}

		code = check5Bits(code, uint(label[i]>>5))
		// least-significant bits in next loop
	}
	code = check5Bits(code, 0)
	for i := 0; i < len(label); i++ {
		code = check5Bits(code, uint(label[i]&31))
	}
	return code, nil
}

// See the “Checksum” subsection in BIP173.
func check5Bits(code uint, v uint) uint {
	b := code >> 25
	code = (code&0x1ffffff)<<5 ^ v
	if b&1 != 0 {
		code ^= 0x3b6a57b2
	}
	if b&2 != 0 {
		code ^= 0x26508e6d
	}
	if b&4 != 0 {
		code ^= 0x1ea119fa
	}
	if b&8 != 0 {
		code ^= 0x3d4233dd
	}
	if b&16 != 0 {
		code ^= 0x2a1462b3
	}
	return code
}
