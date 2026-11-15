package tree_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bpalermo/cgroup-signals/appimage-closure/internal/tree"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"/nix/store/a/bin/x":   "nix/store/a/bin/x",
		"nix//store/./a/":      "nix/store/a",
		"nix/store/a/../b/lib": "nix/store/b/lib",
		"../x":                 "x",
		"/":                    "",
	} {
		if got := tree.Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

// header is an ELF64 header whose section header table ends at the end of the
// file, with whatever follows it.
func header(shoff uint64, shnum uint16, tail string) []byte {
	b := make([]byte, 64)
	copy(b, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint64(b[0x28:], shoff)
	binary.LittleEndian.PutUint16(b[0x3a:], 64)
	binary.LittleEndian.PutUint16(b[0x3c:], shnum)
	b = append(b, make([]byte, 64*int(shnum))...) // the table, at shoff 64
	return append(b, tail...)
}

func TestAppImageOffset(t *testing.T) {
	off, err := tree.AppImageOffset(bytes.NewReader(header(64, 2, "hsqs....")))
	if err != nil || off != 64+2*64 {
		t.Errorf("offset %d, err %v, want %d", off, err, 64+2*64)
	}
	if _, err := tree.AppImageOffset(bytes.NewReader(header(64, 2, "nope...."))); err == nil {
		t.Error("no squashfs magic must fail")
	}
	if _, err := tree.AppImageOffset(bytes.NewReader([]byte("#!/bin/sh\n"))); err == nil {
		t.Error("a script is not an AppImage")
	}
}
