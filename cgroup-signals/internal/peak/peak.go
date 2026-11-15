// Package peak reads a cgroup's memory.peak and resets it through one file
// descriptor, so that each read is the peak since the previous reset.
//
// Since Linux 6.12, a write of any non-empty string to memory.peak resets the
// watermark seen through that file descriptor to the cgroup's current usage
// (Documentation/admin-guide/cgroup-v2.rst). Until the first write, a read
// returns the cgroup's lifetime peak, which is why Open resets right away.
//
// The reset lowers a watermark the kernel shares between all the file
// descriptors that ever wrote (mm/memcontrol.c, peak_write): another process
// resetting the same cgroup's memory.peak, even through its own descriptor,
// cuts this reader's window short. One collector must own the reset.
package peak

import (
	"fmt"
	"io"
	"os"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/cgroupfs"
)

// File is what a Reader needs of an open memory.peak; *os.File is one.
type File interface {
	io.ReaderAt
	io.Writer
	io.Closer
}

// Opener opens a memory.peak file for reading and writing.
type Opener interface {
	Open(path string) (File, error)
}

// OSOpener opens files with os.OpenFile, O_RDWR.
type OSOpener struct{}

// Open implements Opener.
func (OSOpener) Open(path string) (File, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}

// resetString is what Reset writes: the kernel ignores the content of a
// non-empty write.
var resetString = []byte("reset\n")

// Reader holds one memory.peak file descriptor open.
type Reader struct {
	f   File
	buf [32]byte
}

// Open opens path with o and resets it, so the first Read is the peak since
// Open rather than since the cgroup was created.
func Open(o Opener, path string) (*Reader, error) {
	f, err := o.Open(path)
	if err != nil {
		return nil, err
	}
	r := &Reader{f: f}
	if err := r.Reset(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

// Read returns the peak, in bytes, since the last Reset.
func (r *Reader) Read() (uint64, error) {
	// pread at offset 0: the kernel restarts its seq_file at offset 0, so the
	// same descriptor can be read again and again.
	n, err := r.f.ReadAt(r.buf[:], 0)
	if n == 0 && err != nil {
		return 0, fmt.Errorf("read memory.peak: %w", err)
	}
	v, err := cgroupfs.ParseUint(r.buf[:n])
	if err != nil {
		return 0, fmt.Errorf("parse memory.peak: %w", err)
	}
	return v, nil
}

// Reset starts a new window: subsequent Reads through this descriptor report
// the peak from the current usage on.
func (r *Reader) Reset() error {
	if _, err := r.f.Write(resetString); err != nil {
		return fmt.Errorf("reset memory.peak: %w", err)
	}
	return nil
}

// Close closes the descriptor.
func (r *Reader) Close() error {
	return r.f.Close()
}
