package runqlat

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// TestObject checks the embedded object without loading it: the programs are
// the tracepoint ones, the maps are the ones the loader and the collector use,
// and the licence section is one the helpers it calls accept.
func TestObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatal(err)
	}
	for name, section := range map[string]string{
		"sched_wakeup":     "tp_btf/sched_wakeup",
		"sched_wakeup_new": "tp_btf/sched_wakeup_new",
		"sched_switch":     "tp_btf/sched_switch",
	} {
		p := spec.Programs[name]
		if p == nil {
			t.Errorf("no program %s", name)
			continue
		}
		if p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceRawTp || p.SectionName != section {
			t.Errorf("%s: type %v attach %v section %q, want a tp_btf program on %q", name, p.Type, p.AttachType, p.SectionName, section)
		}
		if p.License != "GPL" {
			t.Errorf("%s: license %q, want GPL", name, p.License)
		}
	}
	for name, typ := range map[string]ebpf.MapType{
		"start": ebpf.Hash, "tracked": ebpf.Hash, "below": ebpf.LRUHash,
		"hists": ebpf.PerCPUArray, "missed": ebpf.PerCPUArray,
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != typ {
			t.Errorf("map %s: %v, want type %v", name, m, typ)
		}
	}
	// The Go and C sides of the histogram agree.
	m := spec.Maps["hists"]
	if want := uint32(MaxSlots*8 + 8); m == nil || m.ValueSize != want {
		t.Errorf("hists value size is %v, want %d (MaxSlots slots and the sum, as Hist)", m, want)
	}
	if m != nil && m.MaxEntries != MaxCgroups {
		t.Errorf("hists has %d entries, want MaxCgroups (%d)", m.MaxEntries, MaxCgroups)
	}
}

// TestKernelBTF checks the running kernel's BTF has every field the program
// reads. It needs only a readable /sys/kernel/btf/vmlinux, not root.
func TestKernelBTF(t *testing.T) {
	if Check() != nil {
		t.Skip("no kernel BTF on this host")
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skip(err)
	}
	if missing := KernelHasFields(kernel); len(missing) > 0 {
		t.Errorf("this kernel's BTF lacks %v", missing)
	}
}

// TestLoad loads and attaches the program for real: the verifier accepts it,
// CO-RE relocates against this kernel, and the tracepoints exist. It needs
// root (CAP_BPF and CAP_PERFMON). Run it with the binary Bazel built:
//
//	bazel build //cgroup-signals/internal/runqlat:runqlat_test
//	sudo bazel-bin/cgroup-signals/internal/runqlat/runqlat_test_/runqlat_test -test.v -test.run Load
//
// Under `bazel test` (not root) it skips.
func TestLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root; see the test's comment")
	}
	if err := Check(); err != nil {
		t.Skip(err)
	}
	p, err := Load(16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()

	// Track this process's own cgroup: whatever runs it counts there.
	id := ownCgroupID(t)
	if err := p.Reset(1); err != nil {
		t.Fatal(err)
	}
	if err := p.SetTracked(id, 1); err != nil {
		t.Fatal(err)
	}
	busy(200 * time.Millisecond)
	h, err := p.Hist(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("own cgroup %d: %d delays, sum %v", id, h.Count(), time.Duration(h.SumNS))
	if h.Count() == 0 {
		t.Error("no run-queue delay was counted for a process that was runnable and woken")
	}
	var sum uint64
	for _, c := range h.Slots {
		sum += c
	}
	if sum != h.Count() {
		t.Errorf("slots sum %d != Count %d", sum, h.Count())
	}
	if err := p.DeleteTracked(id); err != nil {
		t.Error(err)
	}
	if err := p.DeleteTracked(id); err != nil {
		t.Errorf("deleting a cgroup that is not tracked is not an error: %v", err)
	}
}

func ownCgroupID(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, line := range bytes.Split(data, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(line, []byte("0::")); ok {
			path = string(rest)
		}
	}
	var st unix.Stat_t
	if err := unix.Stat("/sys/fs/cgroup"+path, &st); err != nil {
		t.Skipf("cannot stat own cgroup %q: %v", path, err)
	}
	return st.Ino
}

// busy keeps the goroutines switching: many short sleeps wake the thread over
// and over, each wakeup being a run-queue wait.
func busy(d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		time.Sleep(200 * time.Microsecond)
	}
}
