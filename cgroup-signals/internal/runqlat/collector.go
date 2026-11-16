package runqlat

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/cgroupfs"
)

const namespace = "cgroup_signals"

// OtherCgroup is the value of the cgroup label of the histogram of everything
// that is under no tracked cgroup (the root, kernel threads, the QoS cgroups
// themselves, ...).
const OtherCgroup = "other"

// The runqueue_scan_errors_total{op} values.
const (
	OpDiscover = "discover"
	OpInode    = "inode"
	OpLimit    = "limit"
	OpMap      = "map"
	OpRead     = "read"
)

var ops = []string{OpDiscover, OpInode, OpLimit, OpMap, OpRead}

var (
	cgroupLabels = []string{"pod_uid", "qos", "cgroup"}

	latencyDesc = prometheus.NewDesc(namespace+"_runqueue_latency_seconds",
		"Run-queue latency: the time from a task of the cgroup (or any cgroup under it) becoming runnable, or being "+
			"preempted while runnable, to it getting on a CPU. A native histogram of schema 0 (bucket bounds are powers of two "+
			"seconds, from 2^-19 s, about 1.9 us; delays up to that are in its bucket, those over 2048 s in (2048, 4096]). "+
			"cgroup=\"other\" is everything under no pod or node-service cgroup. Cumulative since the cgroup was first tracked.",
		cgroupLabels, nil)
	trackedDesc = prometheus.NewDesc(namespace+"_runqueue_tracked_cgroups",
		"Cgroups with a run-queue latency histogram (pods and node services, not counting other).", nil, nil)
	missedDesc = prometheus.NewDesc(namespace+"_runqueue_missed_total",
		"Context switches to a task whose wakeup the program did not see (tasks already runnable when it attached, "+
			"or a wakeup lost to a full table). They are not counted in the histograms.", nil, nil)
)

// Inode returns the kernel's id of the cgroup at path under the cgroup root,
// which is the inode number of its directory.
type Inode func(path string) (uint64, error)

// Config is what New needs.
type Config struct {
	// Store is the loaded program.
	Store Store
	// Missed reads the program's missed-wakeup counter; may be nil.
	Missed func() (uint64, error)
	// FS is the cgroup v2 root, for discovery.
	FS fs.FS
	// Inode gives a cgroup's kernel id.
	Inode Inode
	// MaxTracked caps the tracked cgroups; it must be below MaxCgroups.
	MaxTracked int
	Log        *slog.Logger
}

type entry struct {
	cg    cgroupfs.Cgroup
	id    uint64
	idx   uint32
	since time.Time // when its histogram was zeroed: the series' created timestamp
}

// Collector is a prometheus.Collector over the program's histograms. It owns
// the assignment of histogram indices to cgroups.
type Collector struct {
	cfg Config
	log *slog.Logger

	scanErrors *prometheus.CounterVec

	mu      sync.Mutex
	tracked map[string]*entry // by cgroup path
	free    []uint32          // indices that can be handed out again
	// quarantine holds the indices of cgroups dropped by the last rescan. A
	// dying cgroup's last switches can still be counted for a moment after
	// the loader forgets it; an index is only reused one rescan later, so
	// they cannot land in a new cgroup's histogram.
	quarantine []uint32
	next       uint32 // the next never-used index
	// start is when the program began counting, the created timestamp of
	// cgroup="other".
	start time.Time
}

// New returns a Collector that tracks nothing until Rescan.
func New(cfg Config) *Collector {
	c := &Collector{
		cfg:     cfg,
		log:     cfg.Log,
		tracked: make(map[string]*entry),
		next:    1, // 0 is other
		start:   time.Now(),
		scanErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "runqueue_scan_errors_total",
			Help:      "Errors tracking cgroups or reading the run-queue histograms, by operation. A cgroup that disappears is not an error.",
		}, []string{"op"}),
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	for _, op := range ops {
		c.scanErrors.WithLabelValues(op)
	}
	return c
}

// Run rescans every interval until ctx is done. It does not rescan first:
// call Rescan before serving.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Rescan()
		}
	}
}

// Rescan discovers the pod and node-service cgroups, starts counting for the
// new ones and stops for those that are gone. After a discovery error nothing
// is dropped.
func (c *Collector) Rescan() {
	found, err := cgroupfs.Discover(c.cfg.FS)
	if err != nil {
		c.scanError(OpDiscover, "", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.free = append(c.free, c.quarantine...)
	c.quarantine = c.quarantine[:0]

	seen := make(map[string]bool, len(found))
	for _, cg := range found {
		seen[cg.Path] = true
		c.refresh(cg)
	}
	if err != nil {
		return
	}
	for p := range c.tracked {
		if !seen[p] {
			c.drop(p, "removed")
		}
	}
}

// refresh starts tracking cg, or, if a cgroup of that path is tracked under a
// different kernel id (it was removed and created again), tracks the new one.
func (c *Collector) refresh(cg cgroupfs.Cgroup) {
	id, err := c.cfg.Inode(cg.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return // gone since the listing
	}
	if err != nil {
		c.scanError(OpInode, cg.Path, err)
		return
	}
	if e := c.tracked[cg.Path]; e != nil {
		if e.id == id {
			return
		}
		c.drop(cg.Path, "recreated")
	}
	c.track(cg, id)
}

// index hands out a histogram index, or 0 and false when all are in use.
func (c *Collector) index() (uint32, bool) {
	if n := len(c.free); n > 0 {
		idx := c.free[n-1]
		c.free = c.free[:n-1]
		return idx, true
	}
	if limit := c.limit(); c.next <= uint32(limit) {
		idx := c.next
		c.next++
		return idx, true
	}
	return 0, false
}

func (c *Collector) limit() int {
	if c.cfg.MaxTracked > 0 && c.cfg.MaxTracked < MaxCgroups-1 {
		return c.cfg.MaxTracked
	}
	return MaxCgroups - 1
}

// track starts counting for cg: it zeroes a histogram and then tells the
// program, so nothing counted before is attributed to it. Called with mu held.
func (c *Collector) track(cg cgroupfs.Cgroup, id uint64) {
	idx, ok := c.index()
	if !ok {
		c.scanError(OpLimit, cg.Path, errors.New("too many cgroups"))
		return
	}
	if err := c.cfg.Store.Reset(idx); err != nil {
		c.free = append(c.free, idx)
		c.scanError(OpMap, cg.Path, err)
		return
	}
	if err := c.cfg.Store.SetTracked(id, idx); err != nil {
		c.free = append(c.free, idx)
		c.scanError(OpMap, cg.Path, err)
		return
	}
	c.tracked[cg.Path] = &entry{cg: cg, id: id, idx: idx, since: time.Now()}
	c.log.Debug("tracking cgroup", "path", cg.Path, "id", id, "index", idx)
}

// drop forgets the cgroup at p. Called with mu held.
func (c *Collector) drop(p, why string) {
	e := c.tracked[p]
	if e == nil {
		return
	}
	delete(c.tracked, p)
	if err := c.cfg.Store.DeleteTracked(e.id); err != nil {
		c.scanError(OpMap, p, err)
	}
	c.quarantine = append(c.quarantine, e.idx)
	c.log.Debug("dropped cgroup", "path", p, "reason", why)
}

func (c *Collector) scanError(op, p string, err error) {
	c.scanErrors.WithLabelValues(op).Inc()
	c.log.Warn("scan error", "op", op, "path", p, "err", err)
}

// Close forgets every tracked cgroup.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.tracked {
		c.drop(p, "shutdown")
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- latencyDesc
	ch <- trackedDesc
	ch <- missedDesc
	c.scanErrors.Describe(ch)
}

// Collect implements prometheus.Collector. It reads the histograms; nothing is
// reset, so any number of scrapers can read them.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	paths := make([]string, 0, len(c.tracked))
	for p := range c.tracked {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		e := c.tracked[p]
		c.collectHist(ch, e.idx, e.since, labelValues(e.cg))
	}
	c.collectHist(ch, Other, c.start, []string{"", "", OtherCgroup})
	ch <- prometheus.MustNewConstMetric(trackedDesc, prometheus.GaugeValue, float64(len(c.tracked)))
	if c.cfg.Missed != nil {
		if n, err := c.cfg.Missed(); err != nil {
			c.scanError(OpRead, "", err)
		} else {
			ch <- prometheus.MustNewConstMetric(missedDesc, prometheus.CounterValue, float64(n))
		}
	}
	c.scanErrors.Collect(ch)
}

func (c *Collector) collectHist(ch chan<- prometheus.Metric, idx uint32, since time.Time, lv []string) {
	h, err := c.cfg.Store.Hist(idx)
	if err != nil {
		c.scanError(OpRead, fmt.Sprint(lv), err)
		return
	}
	buckets := h.NativeBuckets()
	ch <- prometheus.MustNewConstNativeHistogram(latencyDesc, h.Count(), float64(h.SumNS)/1e9,
		buckets, nil, 0, Schema, 0, since, lv...)
}

// Schema is the native histogram schema of the latency histograms: 0, bucket
// bounds at powers of two seconds.
const Schema = 0

// SlotBucketOffset maps a slot to its native bucket: slot k, delays of
// (2^(k-20), 2^(k-19)] s, is bucket k-SlotBucketOffset, which schema 0 defines
// the same way.
const SlotBucketOffset = 19

// NativeBuckets returns the histogram's non-empty slots as native histogram
// buckets of schema 0, by bucket index. Slot 0 (up to 2^-19 s, about 1.9 us)
// is bucket -19, not the zero bucket: Prometheus's OTLP ingestion drops a zero
// threshold (it sets 1e-128), which would make those delays zero, and on a
// Raspberry Pi none are that short. The last slot (over 2048 s) is bucket 12,
// (2048, 4096] s.
func (h *Hist) NativeBuckets() map[int]int64 {
	buckets := make(map[int]int64)
	for k, n := range h.Slots {
		if n > 0 {
			buckets[k-SlotBucketOffset] = int64(n)
		}
	}
	return buckets
}

func labelValues(cg cgroupfs.Cgroup) []string {
	return []string{cg.PodUID, cg.QoS, cg.Service}
}
