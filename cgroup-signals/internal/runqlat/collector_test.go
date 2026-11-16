package runqlat

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	podA = "0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab"
	podB = "1b0c5e2f-1a2b-4c3d-8e9f-0123456789ab"
)

func podPath(uid string) string {
	return "kubepods/burstable/pod" + strings.ReplaceAll(uid, "-", "_")
}

// fakeStore is the program's maps in memory, with the same shape: histogram
// 0 always exists, and tracked maps a cgroup id to an index.
type fakeStore struct {
	tracked map[uint64]uint32
	hists   map[uint32]Hist
	resets  []uint32
	failSet error
}

func newFakeStore() *fakeStore {
	return &fakeStore{tracked: map[uint64]uint32{}, hists: map[uint32]Hist{}}
}

func (f *fakeStore) SetTracked(id uint64, idx uint32) error {
	if f.failSet != nil {
		return f.failSet
	}
	f.tracked[id] = idx
	return nil
}

func (f *fakeStore) DeleteTracked(id uint64) error { delete(f.tracked, id); return nil }
func (f *fakeStore) Hist(idx uint32) (Hist, error) { return f.hists[idx], nil }
func (f *fakeStore) Reset(idx uint32) error {
	f.resets = append(f.resets, idx)
	delete(f.hists, idx)
	return nil
}

// cgroups is a fake cgroup tree: directories under a root, each with an id.
type cgroups struct {
	fsys fstest.MapFS
	ids  map[string]uint64
}

func newCgroups() *cgroups {
	return &cgroups{fsys: fstest.MapFS{}, ids: map[string]uint64{}}
}

func (c *cgroups) add(p string, id uint64) {
	c.fsys[p] = &fstest.MapFile{Mode: fs.ModeDir | 0o755}
	c.ids[p] = id
}

func (c *cgroups) remove(p string) {
	delete(c.fsys, p)
	delete(c.ids, p)
}

func (c *cgroups) inode(p string) (uint64, error) {
	id, ok := c.ids[p]
	if !ok {
		return 0, fs.ErrNotExist
	}
	return id, nil
}

func newCollector(c *cgroups, s Store, max int) *Collector {
	return New(Config{Store: s, FS: c.fsys, Inode: c.inode, MaxTracked: max})
}

func gather(t *testing.T, col prometheus.Collector) map[string]*dto.Metric {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(col)
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.Metric{}
	for _, f := range fams {
		for _, m := range f.GetMetric() {
			var lv []string
			for _, l := range m.GetLabel() {
				lv = append(lv, l.GetName()+"="+l.GetValue())
			}
			out[f.GetName()+"{"+strings.Join(lv, ",")+"}"] = m
		}
	}
	return out
}

func TestTrackAssignsIndicesAndLabels(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	cg.add("podruntime/kubelet", 102)
	store := newFakeStore()
	col := newCollector(cg, store, 0)
	col.Rescan()

	want := map[uint64]uint32{101: 1, 102: 2}
	if len(store.tracked) != 2 || store.tracked[101] == 0 || store.tracked[102] == 0 || store.tracked[101] == store.tracked[102] {
		t.Fatalf("tracked = %v, want two distinct non-zero indices for %v", store.tracked, want)
	}
	pod, svc := store.tracked[101], store.tracked[102]
	store.hists[pod] = Hist{Slots: [MaxSlots]uint64{0: 1, 3: 4}, SumNS: 20000}
	store.hists[svc] = Hist{Slots: [MaxSlots]uint64{2: 5}, SumNS: 5000}
	store.hists[Other] = Hist{Slots: [MaxSlots]uint64{MaxSlots - 1: 2}, SumNS: 9e9}

	got := gather(t, col)
	cases := []struct {
		series string
		count  uint64
		sum    float64
	}{
		{`cgroup_signals_runqueue_latency_seconds{cgroup=,pod_uid=` + podA + `,qos=burstable}`, 5, 20e-6},
		{`cgroup_signals_runqueue_latency_seconds{cgroup=kubelet,pod_uid=,qos=}`, 5, 5e-6},
		{`cgroup_signals_runqueue_latency_seconds{cgroup=other,pod_uid=,qos=}`, 2, 9},
	}
	for _, c := range cases {
		m := got[c.series]
		if m == nil {
			t.Fatalf("no series %s in %v", c.series, keys(got))
		}
		h := m.GetHistogram()
		if h.GetSampleCount() != c.count || math.Abs(h.GetSampleSum()-c.sum) > 1e-12 {
			t.Errorf("%s: count %d sum %g, want %d %g", c.series, h.GetSampleCount(), h.GetSampleSum(), c.count, c.sum)
		}
	}
	if v := got["cgroup_signals_runqueue_tracked_cgroups{}"].GetGauge().GetValue(); v != 2 {
		t.Errorf("tracked_cgroups = %v, want 2", v)
	}
}

func keys(m map[string]*dto.Metric) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestNativeBuckets(t *testing.T) {
	h := Hist{Slots: [MaxSlots]uint64{0: 1, 1: 2, 19: 3, MaxSlots - 1: 7}}
	got := h.NativeBuckets()
	want := map[int]int64{-19: 1, -18: 2, 0: 3, 12: 7}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("NativeBuckets() = %v, want %v", got, want)
	}
	if len((&Hist{}).NativeBuckets()) != 0 {
		t.Error("an empty histogram has buckets")
	}
}

// slotByDefinition is the k with 2^k < ns * 2^20 / 1e9 <= 2^(k+1) (0 up to 2
// units, MaxSlots-1 beyond), in exact integer arithmetic.
func slotByDefinition(ns uint64) int {
	u := new(big.Int).Lsh(new(big.Int).SetUint64(ns), 20)
	for k := range MaxSlots - 1 {
		bound := new(big.Int).Lsh(big.NewInt(1e9), uint(k+1))
		if u.Cmp(bound) <= 0 {
			return k
		}
	}
	return MaxSlots - 1
}

func TestSlotOf(t *testing.T) {
	var ns []uint64
	for k := range MaxSlots + 2 {
		// Around every slot edge: floor(1953125 * 2^k / 2048).
		edge := (uint64(1953125) << k) >> 11
		for d := uint64(0); d < 3; d++ {
			ns = append(ns, edge-d, edge+d)
		}
	}
	for n := uint64(0); n < 1<<16; n++ {
		ns = append(ns, n)
	}
	for j := range 64 {
		ns = append(ns, uint64(1)<<j, uint64(1)<<j-1)
	}
	ns = append(ns, math.MaxUint64)
	for _, n := range ns {
		if got, want := slotOf(n), slotByDefinition(n); got != want {
			t.Errorf("slotOf(%d) = %d, want %d", n, got, want)
		}
	}
	// Slot k is native bucket k-19, (2^(k-20), 2^(k-19)] s: 1 ms is in
	// (2^-10, 2^-9] s, bucket -9; exactly 1 s is in (0.5, 1], bucket 0, and
	// 2048 s in bucket 11, the last before the catch-all.
	for _, c := range []struct {
		ns   uint64
		want int
	}{{1e6, -9}, {1e9, 0}, {1e9 + 1, 1}, {2048e9, 11}, {2048e9 + 1, 12}} {
		if got := slotOf(c.ns) - SlotBucketOffset; got != c.want {
			t.Errorf("%d ns is in bucket %d, want %d", c.ns, got, c.want)
		}
	}
}

func TestDropQuarantinesTheIndexForOneRescan(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	store := newFakeStore()
	col := newCollector(cg, store, 0)
	col.Rescan()
	idxA := store.tracked[101]

	cg.remove(podPath(podA))
	cg.add(podPath(podB), 202)
	col.Rescan() // A is dropped; B must not get A's index yet
	if _, ok := store.tracked[101]; ok {
		t.Error("the dropped cgroup is still tracked")
	}
	if idxB := store.tracked[202]; idxB == idxA {
		t.Errorf("a new cgroup got the index %d of one dropped in the same rescan", idxA)
	}

	cg.add("system", 303)
	col.Rescan() // A's index is free now, and handed out zeroed
	if got := store.tracked[303]; got != idxA {
		t.Errorf("index %d was not reused, got %d", idxA, got)
	}
	if last := store.resets[len(store.resets)-1]; last != idxA {
		t.Errorf("the reused histogram was not zeroed: resets %v", store.resets)
	}
}

func TestRecreatedCgroupGetsANewIndexAndID(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	store := newFakeStore()
	col := newCollector(cg, store, 0)
	col.Rescan()
	cg.add(podPath(podA), 999) // same path, new cgroup
	col.Rescan()
	if _, ok := store.tracked[101]; ok {
		t.Error("the old id is still tracked")
	}
	if store.tracked[999] == 0 {
		t.Error("the new id is not tracked")
	}
}

func TestMaxTracked(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	cg.add(podPath(podB), 202)
	store := newFakeStore()
	col := newCollector(cg, store, 1)
	col.Rescan()
	if len(store.tracked) != 1 {
		t.Fatalf("tracked %v, want 1 cgroup", store.tracked)
	}
	got := gather(t, col)
	if v := got[`cgroup_signals_runqueue_scan_errors_total{op=limit}`].GetCounter().GetValue(); v != 1 {
		t.Errorf("scan_errors_total{op=limit} = %v, want 1", v)
	}
	for idx := range store.hists {
		if idx > 1 {
			t.Errorf("index %d is beyond the cap", idx)
		}
	}
}

func TestStoreErrorsAreCountedAndTheCgroupRetried(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	store := newFakeStore()
	store.failSet = errors.New("map is full")
	col := newCollector(cg, store, 0)
	col.Rescan()
	if got := gather(t, col)[`cgroup_signals_runqueue_scan_errors_total{op=map}`].GetCounter().GetValue(); got != 1 {
		t.Errorf("scan_errors_total{op=map} = %v, want 1", got)
	}
	store.failSet = nil
	col.Rescan()
	if store.tracked[101] == 0 {
		t.Error("the cgroup was not tracked once the map accepted it")
	}
}

func TestVanishedBetweenListAndStatIsNotAnError(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	delete(cg.ids, podPath(podA)) // listed, then gone
	col := newCollector(cg, newFakeStore(), 0)
	col.Rescan()
	for op, v := range map[string]float64{OpInode: 0, OpDiscover: 0} {
		if got := gather(t, col)[fmt.Sprintf(`cgroup_signals_runqueue_scan_errors_total{op=%s}`, op)].GetCounter().GetValue(); got != v {
			t.Errorf("op %s = %v, want %v", op, got, v)
		}
	}
}

func TestMissedAndCloseForgetEverything(t *testing.T) {
	cg := newCgroups()
	cg.add(podPath(podA), 101)
	store := newFakeStore()
	col := New(Config{Store: store, FS: cg.fsys, Inode: cg.inode, Missed: func() (uint64, error) { return 7, nil }})
	col.Rescan()
	if v := gather(t, col)["cgroup_signals_runqueue_missed_total{}"].GetCounter().GetValue(); v != 7 {
		t.Errorf("missed_total = %v, want 7", v)
	}
	col.Close()
	if len(store.tracked) != 0 {
		t.Errorf("Close left %v tracked", store.tracked)
	}
}
