package psi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTriggerValidate(t *testing.T) {
	for _, tc := range []struct {
		trigger    Trigger
		privileged bool
		ok         bool
	}{
		{Trigger{100000, 1000000}, true, true}, // the defaults
		{Trigger{100000, 1000000}, false, false},
		{Trigger{100000, 2000000}, false, true},
		{Trigger{150000, 10000000}, false, true},
		{Trigger{500000, 500000}, true, true},
		{Trigger{100000, 499999}, true, false},
		{Trigger{100000, 10000001}, true, false},
		{Trigger{0, 1000000}, true, false},
		{Trigger{1000001, 1000000}, true, false},
	} {
		err := tc.trigger.Validate(tc.privileged)
		if (err == nil) != tc.ok {
			t.Errorf("%v.Validate(privileged=%v) = %v, want ok=%v", tc.trigger, tc.privileged, err, tc.ok)
		}
	}
}

func TestArmWritesTheTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cpu.pressure")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := Arm(path, Trigger{ThresholdUS: 100000, WindowUS: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "some 100000 1000000\x00"; string(data) != want {
		t.Errorf("Arm wrote %q, want %q", data, want)
	}
	if _, err := Arm(filepath.Join(t.TempDir(), "missing"), Trigger{1, 2}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Arm(missing) = %v, want ErrNotExist", err)
	}
}

type recorder struct {
	mu     sync.Mutex
	events map[string]int
	gone   []string
	w      *Watcher
}

func (r *recorder) Event(key string, res Resource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[key+"/"+string(res)]++
}

func (r *recorder) Gone(key string) {
	r.mu.Lock()
	r.gone = append(r.gone, key)
	r.mu.Unlock()
	r.w.Remove(key) // as the collector does, from the handler
}

func (r *recorder) snapshot() (map[string]int, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := make(map[string]int, len(r.events))
	for k, v := range r.events {
		events[k] = v
	}
	return events, append([]string(nil), r.gone...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// socketPair stands in for a PSI trigger fd: out-of-band data on a Unix
// stream socket raises EPOLLPRI on the peer, as a trigger event does, and
// closing the peer raises EPOLLHUP, as removing the cgroup raises EPOLLERR.
func socketPair(t *testing.T) (watched, peer int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fds[0], fds[1]
}

func sendOOB(t *testing.T, fd int) {
	t.Helper()
	if err := unix.Sendto(fd, []byte{'!'}, unix.MSG_OOB, nil); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("kernel without AF_UNIX MSG_OOB (CONFIG_AF_UNIX_OOB)")
		}
		t.Fatal(err)
	}
}

func TestWatcherEventsAndGone(t *testing.T) {
	rec := &recorder{events: map[string]int{}}
	w, err := NewWatcher(Trigger{}, rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.w = w
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	podCPU, podCPUPeer := socketPair(t)
	podMem, podMemPeer := socketPair(t)
	svc, svcPeer := socketPair(t)
	defer func() {
		for _, fd := range []int{podCPUPeer, podMemPeer, svcPeer} {
			_ = unix.Close(fd)
		}
	}()
	for _, a := range []struct {
		key string
		res Resource
		fd  int
	}{{"pod", CPU, podCPU}, {"pod", Memory, podMem}, {"svc", CPU, svc}} {
		if err := w.Add(a.key, a.res, a.fd); err != nil {
			t.Fatal(err)
		}
	}
	if w.Len() != 3 {
		t.Fatalf("Len = %d, want 3", w.Len())
	}

	// In-band data is not an event: only EPOLLPRI is watched.
	if _, err := unix.Write(podCPUPeer, []byte("x")); err != nil {
		t.Fatal(err)
	}
	sendOOB(t, podMemPeer)
	waitFor(t, "the memory event", func() bool { e, _ := rec.snapshot(); return e["pod/memory"] == 1 })
	sendOOB(t, svcPeer)
	waitFor(t, "the svc event", func() bool { e, _ := rec.snapshot(); return e["svc/cpu"] == 1 })
	if e, _ := rec.snapshot(); e["pod/cpu"] != 0 {
		t.Errorf("in-band data counted as %d events", e["pod/cpu"])
	}

	// The peer hanging up is the cgroup going away: Gone, once, and the
	// handler's Remove closes both of the pod's descriptors.
	if err := unix.Close(podCPUPeer); err != nil {
		t.Fatal(err)
	}
	podCPUPeer = -1
	waitFor(t, "Gone", func() bool { _, g := rec.snapshot(); return len(g) > 0 })
	if _, g := rec.snapshot(); len(g) != 1 || g[0] != "pod" {
		t.Errorf("Gone calls = %v, want [pod]", g)
	}
	if w.Len() != 1 {
		t.Errorf("Len after Gone = %d, want 1", w.Len())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Len() != 0 {
		t.Errorf("Len after Close = %d", w.Len())
	}
}
