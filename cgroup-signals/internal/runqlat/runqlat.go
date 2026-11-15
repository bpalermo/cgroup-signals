// Package runqlat loads the run-queue latency eBPF program and exports its
// per-cgroup histograms.
//
// The program (bpf/runqlat.bpf.c) times each task from the moment it becomes
// runnable (sched_wakeup, sched_wakeup_new, or preempted while still runnable
// at sched_switch) to the sched_switch that puts it on a CPU, and counts the
// delay in a log2 histogram of the tracked cgroup the task is in: a pod, a
// node service, or "other". This package assigns the cgroups their histogram
// indices, reads the histograms at each scrape, and turns them into a
// Prometheus histogram.
package runqlat

import (
	"bytes"
	_ "embed" // the BPF object
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	// MaxSlots is the number of slots of a histogram: slot k counts delays
	// of [2^k, 2^(k+1)) microseconds, and the last slot everything above.
	// Equal to MAX_SLOTS in bpf/runqlat.h.
	MaxSlots = 24
	// MaxCgroups is the most histograms the program can hold, "other"
	// included. Equal to MAX_CGROUPS in bpf/runqlat.h.
	MaxCgroups = 4096
	// Other is the histogram of everything under no tracked cgroup.
	Other uint32 = 0
)

// KernelBTF is where the kernel exports its BTF, which the program's CO-RE
// relocations need.
const KernelBTF = "/sys/kernel/btf/vmlinux"

//go:embed runqlat.bpf.o
var object []byte

// Hist is one cgroup's histogram, summed over the CPUs. The layout is that of
// struct hist in bpf/runqlat.h.
type Hist struct {
	Slots [MaxSlots]uint64
	SumNS uint64
}

// Count is the number of delays counted.
func (h *Hist) Count() uint64 {
	var n uint64
	for _, c := range h.Slots {
		n += c
	}
	return n
}

// add adds o to h.
func (h *Hist) add(o *Hist) {
	for i := range h.Slots {
		h.Slots[i] += o.Slots[i]
	}
	h.SumNS += o.SumNS
}

// Upper returns the inclusive upper bound, in seconds, of slot k: delays in
// slot k are under 2^(k+1) microseconds. The last slot has none: +Inf.
func Upper(k int) float64 {
	if k >= MaxSlots-1 {
		return math.Inf(1)
	}
	return float64(uint64(1)<<(k+1)) / 1e6
}

// Store is the program's maps, as the Collector uses them. *Program is one;
// the tests use a fake.
type Store interface {
	// SetTracked makes the cgroup with kernel id id count in histogram idx.
	SetTracked(id uint64, idx uint32) error
	// DeleteTracked stops counting for the cgroup; a cgroup that is not
	// tracked is not an error.
	DeleteTracked(id uint64) error
	// Hist reads histogram idx, summed over the CPUs.
	Hist(idx uint32) (Hist, error)
	// Reset zeroes histogram idx on every CPU.
	Reset(idx uint32) error
}

// objects are the maps and programs of the object, by their names in the C.
type objects struct {
	Tracked *ebpf.Map      `ebpf:"tracked"`
	Gen     *ebpf.Variable `ebpf:"tracked_gen"`
	Hists   *ebpf.Map      `ebpf:"hists"`
	Missed  *ebpf.Map      `ebpf:"missed"`

	Wakeup    *ebpf.Program `ebpf:"sched_wakeup"`
	WakeupNew *ebpf.Program `ebpf:"sched_wakeup_new"`
	Switch    *ebpf.Program `ebpf:"sched_switch"`
}

func (o *objects) close() error {
	var errs []error
	for _, p := range []*ebpf.Program{o.Wakeup, o.WakeupNew, o.Switch} {
		if p != nil {
			errs = append(errs, p.Close())
		}
	}
	for _, m := range []*ebpf.Map{o.Tracked, o.Hists, o.Missed} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	return errors.Join(errs...)
}

// Program is the loaded and attached program.
type Program struct {
	objs  objects
	links []link.Link
	cpus  int

	// genMu orders the bumps of the generation, which the program reads to
	// know whether what it remembered about a task is still true.
	genMu sync.Mutex
	gen   uint32
}

// Check returns an error that says what is missing, if this host cannot run
// the program: no kernel BTF.
func Check() error {
	if _, err := os.Stat(KernelBTF); err != nil {
		return fmt.Errorf("kernel BTF is not available: %w (the kernel needs CONFIG_DEBUG_INFO_BTF, and %s must be readable)", err, KernelBTF)
	}
	return nil
}

// Load loads the program with room for maxCgroups tracked cgroups (and
// "other"), and attaches it to the scheduler's tracepoints. It needs CAP_BPF
// and CAP_PERFMON, and Linux 5.11 or later (older kernels charge the maps
// against RLIMIT_MEMLOCK, which Load does not raise).
func Load(maxCgroups int) (*Program, error) {
	return load(maxCgroups, tidSlots())
}

// load is Load with the size of the per-thread array given.
func load(maxCgroups int, tids uint32) (*Program, error) {
	if maxCgroups < 1 || maxCgroups >= MaxCgroups {
		return nil, fmt.Errorf("max tracked cgroups %d is outside 1..%d", maxCgroups, MaxCgroups-1)
	}
	if err := Check(); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("reading the BPF object: %w", err)
	}
	spec.Maps["hists"].MaxEntries = uint32(maxCgroups) + 1
	spec.Maps["tracked"].MaxEntries = uint32(maxCgroups)
	spec.Maps["tids"].MaxEntries = tids

	p := &Program{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		return nil, fmt.Errorf("loading the BPF program: %w%s", err, loadHint(err))
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		_ = p.objs.close()
		return nil, err
	}
	p.cpus = cpus
	for name, prog := range map[string]*ebpf.Program{
		"sched_wakeup": p.objs.Wakeup, "sched_wakeup_new": p.objs.WakeupNew, "sched_switch": p.objs.Switch,
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("attaching to the %s tracepoint: %w", name, err), p.Close())
		}
		p.links = append(p.links, l)
	}
	return p, nil
}

// maxTidSlots caps the per-thread array (32 bytes a slot, 32 MiB at the cap):
// on a kernel with a larger pid_max (up to 4194304) the tids above it use the
// program's LRU hash, slower but just as exact.
const maxTidSlots = 1 << 20

// tidSlots is the size of the per-thread array: the kernel's pid_max, which no
// tid reaches, within [32768, maxtidSlots].
func tidSlots() uint32 {
	return tidSlotsFor(os.ReadFile)
}

func tidSlotsFor(read func(string) ([]byte, error)) uint32 {
	n := uint32(32768)
	if b, err := read("/proc/sys/kernel/pid_max"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil {
			n = uint32(min(max(v, 32768), maxTidSlots))
		}
	}
	return n
}

func loadHint(err error) string {
	switch {
	case errors.Is(err, unix.EPERM):
		return " (needs CAP_BPF and CAP_PERFMON; on a kernel before 5.11 also a raised RLIMIT_MEMLOCK)"
	case errors.Is(err, fs.ErrNotExist):
		return " (does the kernel have the sched_wakeup and sched_switch BTF tracepoints?)"
	}
	return ""
}

// Close detaches and unloads the program.
func (p *Program) Close() error {
	var errs []error
	for _, l := range p.links {
		errs = append(errs, l.Close())
	}
	p.links = nil
	errs = append(errs, p.objs.close())
	return errors.Join(errs...)
}

// bumpGen advances the generation of the tracked set. The program remembers,
// per task and per container cgroup, the histogram index it resolved, and
// trusts it only while the generation is the one it was resolved under; so
// this runs AFTER every change to the tracked map, and the next switch
// resolves again. It retries, because a change whose bump is lost leaves what
// the program remembered trusted.
func (p *Program) bumpGen() error {
	p.genMu.Lock()
	defer p.genMu.Unlock()
	p.gen++
	var err error
	for range 3 {
		if err = p.objs.Gen.Set(p.gen); err == nil {
			return nil
		}
	}
	return fmt.Errorf("advancing the generation: %w", err)
}

// SetTracked implements Store. If it returns an error the cgroup is not
// tracked: a change whose generation bump failed is undone, so the caller can
// hand the index to another cgroup.
func (p *Program) SetTracked(id uint64, idx uint32) error {
	if err := p.objs.Tracked.Put(id, idx); err != nil {
		return err
	}
	err := p.bumpGen()
	if err == nil {
		return nil
	}
	if derr := p.objs.Tracked.Delete(id); derr != nil && !errors.Is(derr, ebpf.ErrKeyNotExist) {
		derr = fmt.Errorf("undoing the change: %w", derr)
		err = errors.Join(err, derr)
	}
	return errors.Join(err, p.bumpGen())
}

// DeleteTracked implements Store.
func (p *Program) DeleteTracked(id uint64) error {
	err := p.objs.Tracked.Delete(id)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		err = nil
	}
	return errors.Join(err, p.bumpGen())
}

// Hist implements Store.
func (p *Program) Hist(idx uint32) (Hist, error) {
	var perCPU []Hist
	if err := p.objs.Hists.Lookup(idx, &perCPU); err != nil {
		return Hist{}, fmt.Errorf("reading histogram %d: %w", idx, err)
	}
	var sum Hist
	for i := range perCPU {
		sum.add(&perCPU[i])
	}
	return sum, nil
}

// Reset implements Store.
func (p *Program) Reset(idx uint32) error {
	return p.objs.Hists.Put(idx, make([]Hist, p.cpus))
}

// Missed is the number of switches to a task whose wakeup the program did not
// see: tasks that were already runnable when it attached, and wakeups lost to
// a full table.
func (p *Program) Missed() (uint64, error) {
	var perCPU []uint64
	if err := p.objs.Missed.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n, nil
}

// KernelHasFields reports which of the kernel structures' fields the program
// reads are missing from the kernel's BTF; none, for a kernel that can run it.
func KernelHasFields(kernel *btf.Spec) []string {
	var missing []string
	for _, s := range []struct {
		name   string
		fields []string // any of; the first that exists counts
	}{
		{"task_struct", []string{"__state", "state"}},
		{"task_struct", []string{"pid"}},
		{"task_struct", []string{"cgroups"}},
		{"css_set", []string{"dfl_cgrp"}},
		{"cgroup", []string{"kn"}},
		{"kernfs_node", []string{"parent", "__parent"}},
		{"kernfs_node", []string{"id"}},
	} {
		var st *btf.Struct
		if err := kernel.TypeByName(s.name, &st); err != nil {
			missing = append(missing, s.name)
			continue
		}
		if !hasAnyMember(st, s.fields) {
			missing = append(missing, s.name+"."+s.fields[0])
		}
	}
	return missing
}

func hasAnyMember(st *btf.Struct, names []string) bool {
	for _, m := range st.Members {
		for _, n := range names {
			if m.Name == n {
				return true
			}
		}
	}
	return false
}
