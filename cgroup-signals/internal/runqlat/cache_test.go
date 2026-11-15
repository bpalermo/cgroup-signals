package runqlat

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

// ownCgroupPath is this process's cgroup, relative to the cgroup root.
func ownCgroupPath(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest
		}
	}
	t.Skip("no cgroup v2 entry in /proc/self/cgroup")
	return ""
}

// makeCgroup creates a cgroup at the root of the hierarchy and returns its
// name and kernel id; it is removed when the test ends.
func makeCgroup(t *testing.T, name string) (dir string, id uint64) {
	t.Helper()
	dir = filepath.Join(cgroupRoot, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return dir, st.Ino
}

// moveSelf moves this whole process to the cgroup at dir.
func moveSelf(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), fmt.Appendf(nil, "%d", os.Getpid()), 0o644); err != nil {
		t.Fatalf("moving into %s: %v", dir, err)
	}
}

// TestCacheInvalidation checks that what the program remembers per task (the
// histogram index of the task's cgroup) is not trusted after it stops being
// true: the task moved to another cgroup, a cgroup was tracked or dropped, or
// an index was handed to another cgroup. It needs root and a cgroup v2 host,
// like TestLoad, and skips otherwise.
func TestCacheInvalidation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := Check(); err != nil {
		t.Skip(err)
	}
	home := filepath.Join(cgroupRoot, ownCgroupPath(t))
	dirA, idA := makeCgroup(t, "cgsig-test-a")
	dirB, idB := makeCgroup(t, "cgsig-test-b")
	_, idC := makeCgroup(t, "cgsig-test-c")

	p, err := Load(16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		moveSelf(t, home) // before the cgroups are removed
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, i := range []uint32{Other, 1, 2, 3} {
		if err := p.Reset(i); err != nil {
			t.Fatal(err)
		}
	}
	counts := func() [4]uint64 {
		var c [4]uint64
		for i := range c {
			h, err := p.Hist(uint32(i))
			if err != nil {
				t.Fatal(err)
			}
			c[i] = h.Count()
		}
		return c
	}
	// run returns how many delays each histogram gained while this process
	// ran in dir.
	run := func(dir string) (gained [4]uint64) {
		moveSelf(t, dir)
		before := counts()
		busy(200 * time.Millisecond)
		after := counts()
		for i := range gained {
			gained[i] = after[i] - before[i]
		}
		return gained
	}

	for _, s := range []struct {
		id  uint64
		idx uint32
	}{{idA, 1}, {idB, 2}} {
		if err := p.SetTracked(s.id, s.idx); err != nil {
			t.Fatal(err)
		}
	}

	// In A, counted in 1; the program now remembers 1 for these threads.
	if g := run(dirA); g[1] == 0 {
		t.Fatalf("in a tracked cgroup, nothing was counted in its histogram: %v", g)
	}
	// Moved to B: the remembered index is for another cgroup.
	if g := run(dirB); g[2] == 0 || g[1] != 0 {
		t.Errorf("after moving to another cgroup: gained %v, want histogram 2 only (not 1)", g)
	}

	// Back in A with 1 remembered, A is dropped and index 1 goes to C: the
	// threads are now under no tracked cgroup, and must not count in 1.
	run(dirA)
	if err := p.DeleteTracked(idA); err != nil {
		t.Fatal(err)
	}
	if err := p.Reset(1); err != nil {
		t.Fatal(err)
	}
	if err := p.SetTracked(idC, 1); err != nil {
		t.Fatal(err)
	}
	if g := run(dirA); g[1] != 0 || g[Other] == 0 {
		t.Errorf("after the index was reused: gained %v, want other only (not 1)", g)
	}

	// Remembered as "other", then tracked: the next switches count there.
	if err := p.SetTracked(idA, 3); err != nil {
		t.Fatal(err)
	}
	if g := run(dirA); g[3] == 0 {
		t.Errorf("after the cgroup was tracked: gained %v, want histogram 3", g)
	}
}
