package peak_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/peak"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/peak/peaktest"
)

func TestReaderWindows(t *testing.T) {
	f := &peaktest.File{}
	f.Charge(1000) // the lifetime peak, before Open
	f.Charge(200)
	r, err := peak.Open(peaktest.Opener{"p": f}, "p")
	if err != nil {
		t.Fatal(err)
	}
	if f.Writes() != 1 {
		t.Fatalf("Open made %d writes, want 1 (the reset)", f.Writes())
	}
	window := func() uint64 {
		t.Helper()
		v, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Reset(); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// The first window starts at Open: the lifetime peak of 1000 is not in it.
	f.Charge(600)
	f.Charge(300)
	if v := window(); v != 600 {
		t.Errorf("first window = %d, want 600", v)
	}
	// A quiet window reports the usage at its start.
	if v := window(); v != 300 {
		t.Errorf("quiet window = %d, want 300", v)
	}
	f.Charge(900)
	f.Charge(100)
	if v := window(); v != 900 {
		t.Errorf("spike window = %d, want 900", v)
	}
	if err := r.Close(); err != nil || !f.Closed() {
		t.Errorf("Close = %v, closed %v", err, f.Closed())
	}
}

func TestReaderErrors(t *testing.T) {
	f := &peaktest.File{}
	r, err := peak.Open(peaktest.Opener{"p": f}, "p")
	if err != nil {
		t.Fatal(err)
	}
	f.Fail(unix.ENODEV)
	if _, err := r.Read(); !errors.Is(err, unix.ENODEV) {
		t.Errorf("Read error = %v, want ENODEV", err)
	}
	if err := r.Reset(); !errors.Is(err, unix.ENODEV) {
		t.Errorf("Reset error = %v, want ENODEV", err)
	}

	if _, err := peak.Open(peaktest.Opener{}, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open(missing) error = %v", err)
	}
	g := &peaktest.File{}
	g.Fail(unix.EACCES)
	if _, err := peak.Open(peaktest.Opener{"p": g}, "p"); !errors.Is(err, unix.EACCES) || !g.Closed() {
		t.Errorf("Open with a failing reset = %v, closed %v; want EACCES and the file closed", err, g.Closed())
	}
}

// TestOSOpener goes through a real descriptor: Read preads offset 0 and
// Reset writes through the same descriptor.
func TestOSOpener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.peak")
	if err := os.WriteFile(path, []byte("12345678901234567890\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := peak.Open(peak.OSOpener{}, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "reset\n") {
		t.Errorf("file after Open = %q, want the reset written at its start", data)
	}
	if err := os.WriteFile(path, []byte("4096\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, err := r.Read(); err != nil || v != 4096 {
		t.Errorf("Read = %d, %v; want 4096", v, err)
	}
	// Reading again through the same descriptor starts over at offset 0.
	if v, err := r.Read(); err != nil || v != 4096 {
		t.Errorf("second Read = %d, %v; want 4096", v, err)
	}
}
