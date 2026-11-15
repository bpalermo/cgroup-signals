package tree

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"

	"github.com/CalebQ42/squashfs"
)

var squashMagic = []byte("hsqs")

// AppImageOffset is where an AppImage's squashfs starts: the end of the ELF
// runtime that precedes it, that is the end of its section header table (the
// type 2 AppImage convention, the same number `--appimage-offset` prints).
func AppImageOffset(r io.ReaderAt) (int64, error) {
	var h [64]byte
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return 0, fmt.Errorf("reading the ELF header: %w", err)
	}
	if string(h[:4]) != elf.ELFMAG || h[elf.EI_CLASS] != byte(elf.ELFCLASS64) || h[elf.EI_DATA] != byte(elf.ELFDATA2LSB) {
		return 0, errors.New("not a little-endian ELF64 file")
	}
	shoff := binary.LittleEndian.Uint64(h[0x28:])
	shentsize := uint64(binary.LittleEndian.Uint16(h[0x3a:]))
	shnum := uint64(binary.LittleEndian.Uint16(h[0x3c:]))
	off := int64(shoff + shentsize*shnum)
	var m [4]byte
	if _, err := r.ReadAt(m[:], off); err != nil || !slices.Equal(m[:], squashMagic) {
		return 0, fmt.Errorf("no squashfs superblock at offset %d, past the ELF's section headers", off)
	}
	return off, nil
}

type squash struct {
	fs squashfs.FS
}

// OpenAppImage reads the squashfs embedded in the AppImage at path. The file
// stays open for the life of the process.
func OpenAppImage(path string) (Tree, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	off, err := AppImageOffset(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r, err := squashfs.NewReaderAtOffset(f, off)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return squash{fs: r.FS}, nil
}

func (s squash) open(name string) (*squashfs.File, error) {
	if name == "" {
		name = "."
	}
	return s.fs.OpenFile(name)
}

func (s squash) Lstat(name string) (Node, error) {
	f, err := s.open(name)
	if err != nil {
		return Node{}, err
	}
	defer f.Close()
	return Node{Mode: f.Mode(), Target: f.SymlinkPath()}, nil
}

func (s squash) ReadFile(name string) ([]byte, error) {
	f, err := s.open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if !f.IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errors.New("not a regular file")}
	}
	return io.ReadAll(f)
}

func (s squash) ReadDir(name string) ([]string, error) {
	ents, err := s.fs.ReadDir(name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, nil
}
