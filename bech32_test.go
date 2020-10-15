package bech32

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormat(t *testing.T) {
	got, err := Format("test", make([]byte, 20), 160)
	if err != nil {
		t.Fatalf("Format(\"test\", [20]byte[:], 160) got error %s", err)
	}
	const want = "test1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql6aptf"
	if got != want {
		t.Errorf("Format(\"test\", [20]byte[:], 160) got %q, want %q", got, want)
	}
}

func TestParse(t *testing.T) {
	const serial = "test1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql6aptf"
	label, data, padding, err := Parse(serial)
	if err != nil {
		t.Fatalf("Parse(%q) got error %s", serial, err)
	}
	if label != "test" {
		t.Errorf("Parse(%q) got label %q, want \"test\"", serial, label)
	}
	if !bytes.Equal(data, make([]byte, 20)) {
		t.Errorf("Parse(%q) got %#x, want 20 zero bytes", serial, data)
	}
	if padding != 0 {
		t.Errorf("Parse(%q) got padding count %d, want 0", serial, padding)
	}
}

func TestValid(t *testing.T) {
	tests := []string{
		"A12UEL5L",
		"a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
		"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
		"?1ezyfcl",
	}

	for _, s := range tests {
		label, data, padding, err := Parse(s)
		if err != nil {
			t.Errorf("%q got error %s", s, err)
		}

		s2, err := Format(label, data, len(data)*8-padding)
		if err != nil {
			t.Errorf("%q recoding got error %s", s, err)
		}
		if lower := strings.ToLower(s); lower != s2 {
			t.Errorf("%q recoded to %s, want %q", s, s2, lower)
			continue
		}
	}
}

func TestInvalid(t *testing.T) {
	tests := []string{
		"\x201nwldj5", // HRP character out of range
		"\x7F1axkwrx", // HRP character out of range
		"\x801eym55h", // HRP character out of range
		"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", // overall max length exceeded
		"pzry9x0s0muk",  // No separator character
		"1pzry9x0s0muk", // Empty HRP
		"x1b4n0q5v",     // Invalid data character
		"li1dgmt3",      // Too short checksum
		"de1lg7wt\xFF",  // Invalid character in checksum
		"A1G7SGD8",      // checksum calculated with uppercase form of HRP
		"10a06t8",       // empty HRP
		"1qzzfhee",      // empty HRP
	}

	for _, s := range tests {
		_, _, _, err := Parse(s)
		if err == nil {
			t.Errorf("no error for %q", s)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, err := Parse("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormat(b *testing.B) {
	label, data, padding, err := Parse("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")
	if err != nil {
		b.Fatal(err)
	}
	bitN := len(data)*8 - padding

	for i := 0; i < b.N; i++ {
		_, err := Format(label, data, bitN)
		if err != nil {
			b.Fatal(err)
		}
	}
}
