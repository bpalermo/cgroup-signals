package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/peak/peaktest"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/psi"
)

const (
	podUID  = "0b0c5e2f-1a2b-4c3d-8e9f-0123456789ab"
	podPath = "kubepods/burstable/pod0b0c5e2f_1a2b_4c3d_8e9f_0123456789ab"
	podSel  = `cgroup="",pod_uid="` + podUID + `",qos="burstable"`
	svcSel  = `cgroup="kubelet",pod_uid="",qos=""`
)

// fakePSI records the triggers the collector arms.
type fakePSI struct {
	mu      sync.Mutex
	watched map[string][]string // key -> paths
	removed []string
	err     error
}

func (f *fakePSI) Watch(key string, _ psi.Resource, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.watched[key] = append(f.watched[key], path)
	return nil
}

func (f *fakePSI) Remove(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.watched, key)
	f.removed = append(f.removed, key)
}

func (f *fakePSI) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, paths := range f.watched {
		n += len(paths)
	}
	return n
}

type fixture struct {
	root  string
	peaks peaktest.Opener
	psi   *fakePSI
	c     *Collector
	reg   *prometheus.Registry
}

// newFixture builds a cgroup tree with one Burstable pod and the kubelet,
// each with memory.events and a fake memory.peak.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{root: t.TempDir(), peaks: peaktest.Opener{}, psi: &fakePSI{watched: map[string][]string{}}}
	f.addCgroup(t, podPath)
	f.addCgroup(t, "podruntime/kubelet")
	f.c = New(Config{Root: f.root, Peaks: f.peaks, PSI: f.psi})
	f.reg = prometheus.NewPedanticRegistry()
	f.reg.MustRegister(f.c)
	return f
}

func (f *fixture) addCgroup(t *testing.T, p string) {
	t.Helper()
	dir := filepath.Join(f.root, p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.writeEvents(t, p, "low 0\nhigh 5\nmax 2\noom 1\noom_kill 1\noom_group_kill 0\nsock_throttled 9\n")
	f.writeStat(t, p, "anon 1000\nfile 2000\nkernel 300\nkernel_stack 50\nshmem 7\nfile_mapped 11\n")
	f.peaks[filepath.Join(dir, "memory.peak")] = &peaktest.File{}
}

func (f *fixture) writeEvents(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, p, "memory.events"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) writeStat(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, p, "memory.stat"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) peak(p string) *peaktest.File {
	return f.peaks[filepath.Join(f.root, p, "memory.peak")]
}

// scrape gathers the registry into "name{labels}" -> value.
func (f *fixture) scrape(t *testing.T) map[string]float64 {
	t.Helper()
	families, err := f.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			out[mf.GetName()+"{"+labelString(m)+"}"] = value(m)
		}
	}
	return out
}

func labelString(m *dto.Metric) string {
	var parts []string
	for _, lp := range m.GetLabel() {
		parts = append(parts, fmt.Sprintf("%s=%q", lp.GetName(), lp.GetValue()))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func value(m *dto.Metric) float64 {
	switch {
	case m.Gauge != nil:
		return m.GetGauge().GetValue()
	case m.Counter != nil:
		return m.GetCounter().GetValue()
	}
	return 0
}

// norm sorts the labels of a "name{labels}" key, the order labelString
// produces, so that tests can write them in any order.
func norm(key string) (string, []string) {
	name, rest, _ := strings.Cut(key, "{")
	var pairs []string
	for _, p := range strings.Split(strings.TrimSuffix(rest, "}"), ",") {
		if p != "" {
			pairs = append(pairs, p)
		}
	}
	sort.Strings(pairs)
	return name, pairs
}

func expect(t *testing.T, got map[string]float64, want map[string]float64) {
	t.Helper()
	for k, v := range want {
		name, pairs := norm(k)
		nk := name + "{" + strings.Join(pairs, ",") + "}"
		gv, ok := got[nk]
		if !ok {
			t.Errorf("missing %s", nk)
		} else if gv != v {
			t.Errorf("%s = %v, want %v", nk, gv, v)
		}
	}
}

// absent fails if any series of the metric in sel has all of sel's labels.
func absent(t *testing.T, got map[string]float64, sel string) {
	t.Helper()
	name, want := norm(sel)
	for k := range got {
		n, pairs := norm(k)
		if n != name {
			continue
		}
		all := true
		for _, w := range want {
			all = all && slices.Contains(pairs, w)
		}
		if all {
			t.Errorf("%s present, want it gone", k)
		}
	}
}

func TestRescanTracksPodsAndServices(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()

	wantPaths := []string{
		filepath.Join(f.root, podPath, "cpu.pressure"),
		filepath.Join(f.root, podPath, "memory.pressure"),
	}
	if got := f.psi.watched[podPath]; !slices.Equal(got, wantPaths) {
		t.Errorf("PSI triggers on the pod = %v, want %v", got, wantPaths)
	}
	if got := len(f.psi.watched["podruntime/kubelet"]); got != 2 {
		t.Errorf("PSI triggers on the kubelet = %d, want 2", got)
	}
	expect(t, f.scrape(t), map[string]float64{
		"cgroup_signals_tracked_cgroups{}":                                          2,
		"cgroup_signals_psi_trigger_fds{}":                                          4,
		`cgroup_signals_psi_trigger_events_total{` + podSel + `,resource="cpu"}`:    0,
		`cgroup_signals_psi_trigger_events_total{` + podSel + `,resource="memory"}`: 0,
		`cgroup_signals_psi_trigger_events_total{` + svcSel + `,resource="cpu"}`:    0,
		`cgroup_signals_scan_errors_total{op="discover"}`:                           0,
	})

	// A second rescan opens nothing again: the resets are Open's and the
	// scrape's.
	f.c.Rescan()
	if got := f.peak(podPath).Writes(); got != 2 {
		t.Errorf("memory.peak resets after two rescans and one scrape = %d, want 2", got)
	}
}

func TestPeakIsSinceThePreviousScrape(t *testing.T) {
	f := newFixture(t)
	p := f.peak(podPath)
	p.Charge(1 << 30) // before tracking: not in any window
	p.Charge(100 << 20)
	f.c.Rescan()

	p.Charge(700 << 20)
	p.Charge(200 << 20)
	expect(t, f.scrape(t), map[string]float64{"cgroup_signals_memory_peak_bytes{" + podSel + "}": 700 << 20})
	expect(t, f.scrape(t), map[string]float64{"cgroup_signals_memory_peak_bytes{" + podSel + "}": 200 << 20})
	p.Charge(300 << 20)
	expect(t, f.scrape(t), map[string]float64{
		"cgroup_signals_memory_peak_bytes{" + podSel + "}": 300 << 20,
		"cgroup_signals_memory_peak_bytes{" + svcSel + "}": 0,
	})
}

func TestMemoryEvents(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	got := f.scrape(t)
	for event, v := range map[string]float64{"low": 0, "high": 5, "max": 2, "oom": 1, "oom_kill": 1, "oom_group_kill": 0} {
		expect(t, got, map[string]float64{
			`cgroup_signals_memory_events_total{` + podSel + `,event="` + event + `"}`: v,
			`cgroup_signals_memory_events_total{` + svcSel + `,event="` + event + `"}`: v,
		})
	}
	absent(t, got, `cgroup_signals_memory_events_total{`+podSel+`,event="sock_throttled"}`)

	f.writeEvents(t, podPath, "garbage\n")
	expect(t, f.scrape(t), map[string]float64{`cgroup_signals_scan_errors_total{op="memory_events"}`: 1})
}

func TestMemoryStat(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	got := f.scrape(t)
	for typ, v := range map[string]float64{"anon": 1000, "file": 2000, "kernel": 300} {
		expect(t, got, map[string]float64{
			`cgroup_signals_memory_stat_bytes{` + podSel + `,type="` + typ + `"}`: v,
			`cgroup_signals_memory_stat_bytes{` + svcSel + `,type="` + typ + `"}`: v,
		})
	}
	for _, typ := range []string{"kernel_stack", "shmem", "file_mapped"} {
		absent(t, got, `cgroup_signals_memory_stat_bytes{`+podSel+`,type="`+typ+`"}`)
	}

	// A kernel before 5.18 has no "kernel" key: the others are still exported.
	f.writeStat(t, podPath, "anon 5\nfile 6\n")
	got = f.scrape(t)
	expect(t, got, map[string]float64{`cgroup_signals_memory_stat_bytes{` + podSel + `,type="anon"}`: 5})
	absent(t, got, `cgroup_signals_memory_stat_bytes{`+podSel+`,type="kernel"}`)

	// A parse error is counted, and the peak is still read and reset.
	f.writeStat(t, podPath, "garbage\n")
	f.peak(podPath).Charge(42)
	f.peak(podPath).Charge(10)
	got = f.scrape(t)
	expect(t, got, map[string]float64{
		`cgroup_signals_scan_errors_total{op="memory_stat"}`: 1,
		"cgroup_signals_memory_peak_bytes{" + podSel + "}":   42,
	})
	// Reset: the next window starts from the current usage.
	expect(t, f.scrape(t), map[string]float64{"cgroup_signals_memory_peak_bytes{" + podSel + "}": 10})
}

func TestRemovedCgroupIsDropped(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	if err := os.RemoveAll(filepath.Join(f.root, podPath)); err != nil {
		t.Fatal(err)
	}
	f.c.Rescan()

	if !f.peak(podPath).Closed() {
		t.Error("memory.peak of the removed pod is still open")
	}
	if !slices.Contains(f.psi.removed, podPath) {
		t.Errorf("PSI triggers of the removed pod were not removed: %v", f.psi.removed)
	}
	got := f.scrape(t)
	absent(t, got, "cgroup_signals_memory_peak_bytes{"+podSel)
	absent(t, got, "cgroup_signals_psi_trigger_events_total{"+podSel)
	expect(t, got, map[string]float64{
		"cgroup_signals_tracked_cgroups{}": 1,
		"cgroup_signals_psi_trigger_fds{}": 2,
	})
}

func TestVanishedMidScrapeIsDroppedQuietly(t *testing.T) {
	for name, vanish := range map[string]func(t *testing.T, f *fixture){
		// kernfs fails reads of a removed cgroup's open files with ENODEV.
		"ENODEV": func(_ *testing.T, f *fixture) { f.peak(podPath).Fail(unix.ENODEV) },
		// Any error, once the directory is gone.
		"directory gone": func(t *testing.T, f *fixture) {
			f.peak(podPath).Fail(errors.New("some error"))
			if err := os.RemoveAll(filepath.Join(f.root, podPath)); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.c.Rescan()
			vanish(t, f)
			got := f.scrape(t)
			absent(t, got, "cgroup_signals_memory_peak_bytes{"+podSel)
			absent(t, got, "cgroup_signals_memory_events_total{"+podSel)
			expect(t, got, map[string]float64{
				"cgroup_signals_tracked_cgroups{}":                  1,
				`cgroup_signals_scan_errors_total{op="peak_read"}`:  0,
				`cgroup_signals_scan_errors_total{op="peak_reset"}`: 0,
			})
			if !f.peak(podPath).Closed() {
				t.Error("memory.peak of the vanished pod is still open")
			}
		})
	}
}

func TestReadErrorOnALiveCgroupIsCounted(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	f.peak(podPath).Fail(unix.EIO)
	expect(t, f.scrape(t), map[string]float64{
		`cgroup_signals_scan_errors_total{op="peak_read"}`: 1,
		"cgroup_signals_tracked_cgroups{}":                 2,
		// memory.events is still read.
		`cgroup_signals_memory_events_total{` + podSel + `,event="high"}`: 5,
	})
}

func TestOpenErrorsKeepTheCgroupTracked(t *testing.T) {
	f := newFixture(t)
	delete(f.peaks, filepath.Join(f.root, podPath, "memory.peak")) // e.g. a kernel before 6.12: no write
	f.psi.err = unix.EINVAL
	f.c.Rescan()
	got := f.scrape(t)
	expect(t, got, map[string]float64{
		`cgroup_signals_scan_errors_total{op="peak_open"}`:               1,
		`cgroup_signals_scan_errors_total{op="psi_arm"}`:                 4,
		"cgroup_signals_tracked_cgroups{}":                               2,
		`cgroup_signals_memory_events_total{` + podSel + `,event="oom"}`: 1,
	})
	absent(t, got, "cgroup_signals_memory_peak_bytes{"+podSel)
	// Not retried on every rescan.
	f.c.Rescan()
	expect(t, f.scrape(t), map[string]float64{`cgroup_signals_scan_errors_total{op="peak_open"}`: 1})
}

func TestPSIHandler(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	f.c.Event(podPath, psi.Memory)
	f.c.Event(podPath, psi.Memory)
	f.c.Event("podruntime/kubelet", psi.CPU)
	f.c.Event("unknown", psi.CPU)
	expect(t, f.scrape(t), map[string]float64{
		`cgroup_signals_psi_trigger_events_total{` + podSel + `,resource="memory"}`: 2,
		`cgroup_signals_psi_trigger_events_total{` + podSel + `,resource="cpu"}`:    0,
		`cgroup_signals_psi_trigger_events_total{` + svcSel + `,resource="cpu"}`:    1,
	})

	f.c.Gone(podPath)
	f.c.Event(podPath, psi.CPU) // late: must not bring the series back
	got := f.scrape(t)
	absent(t, got, "cgroup_signals_psi_trigger_events_total{"+podSel)
	absent(t, got, "cgroup_signals_memory_peak_bytes{"+podSel)
	if !f.peak(podPath).Closed() {
		t.Error("memory.peak still open after Gone")
	}
}

// failingFS fails ReadDir of one directory.
type failingFS struct {
	fs.FS
	dir string
}

func (f failingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.dir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: unix.EIO}
	}
	return fs.ReadDir(f.FS, name)
}

func TestDiscoveryErrorDropsNothing(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	// The burstable directory cannot be listed, so its pod is not found,
	// but a failed listing is not a removal.
	f.c.fsys = failingFS{FS: os.DirFS(f.root), dir: "kubepods/burstable"}
	f.c.Rescan()
	expect(t, f.scrape(t), map[string]float64{
		`cgroup_signals_scan_errors_total{op="discover"}`: 1,
		"cgroup_signals_tracked_cgroups{}":                2,
	})
}

func TestMaxTracked(t *testing.T) {
	f := newFixture(t)
	f.c.maxTracked = 1
	f.c.Rescan()
	expect(t, f.scrape(t), map[string]float64{
		"cgroup_signals_tracked_cgroups{}":             1,
		`cgroup_signals_scan_errors_total{op="limit"}`: 1,
	})
}

func TestClose(t *testing.T) {
	f := newFixture(t)
	f.c.Rescan()
	f.c.Close()
	if !f.peak(podPath).Closed() || !f.peak("podruntime/kubelet").Closed() {
		t.Error("Close left memory.peak files open")
	}
	if f.psi.Len() != 0 {
		t.Errorf("Close left %d trigger fds", f.psi.Len())
	}
}
