// Package peaktest fakes memory.peak for tests.
package peaktest

import (
	"errors"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/peak"
)

// File models one memory.peak file descriptor with the kernel's per-fd
// semantics (mm/memcontrol.c, peak_show and peak_write): until the first
// write a read returns the cgroup's lifetime watermark; a write sets the
// descriptor's watermark to the current usage, and later reads return the
// highest usage since.
type File struct {
	mu       sync.Mutex
	usage    uint64
	lifetime uint64
	fdPeak   *uint64
	writes   int
	closed   bool
	err      error
}

// Charge sets the cgroup's usage, raising the watermarks.
func (f *File) Charge(usage uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage = usage
	f.lifetime = max(f.lifetime, usage)
	if f.fdPeak != nil {
		*f.fdPeak = max(*f.fdPeak, usage)
	}
}

// Fail makes every later call return err, as the kernel returns ENODEV once
// the cgroup is removed.
func (f *File) Fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// Writes is the number of resets.
func (f *File) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// Closed reports whether Close was called.
func (f *File) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// ReadAt implements peak.File. Only offset 0 is supported.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	if off != 0 {
		return 0, errors.New("peaktest: read at a non-zero offset")
	}
	v := f.lifetime
	if f.fdPeak != nil {
		v = *f.fdPeak
	}
	return copy(p, strconv.FormatUint(v, 10)+"\n"), io.EOF
}

// Write implements peak.File: any non-empty write resets.
func (f *File) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	if len(p) == 0 {
		return 0, errors.New("peaktest: empty write")
	}
	u := f.usage
	f.fdPeak = &u
	f.writes++
	return len(p), nil
}

// Close implements peak.File.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// Opener opens the Files in a map by path; any other path does not exist.
type Opener map[string]*File

// Open implements peak.Opener.
func (o Opener) Open(path string) (peak.File, error) {
	f, ok := o[path]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}
	return f, nil
}
