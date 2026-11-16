package runqlat

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/bits"
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
			"preempted while runnable, to it getting on a CPU. Bucket bounds are powers of two microseconds (the "+
			"--runqueue-bucket-* flags pick which). "+
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
	// Slots are the slots whose upper bounds are the exported buckets, in
	// increasing order (see BucketSlots); nil exports every slot.
	Slots []int
	Log   *slog.Logger
}

type entry struct {
	cg  cgroupfs.Cgroup
	id  uint64
	idx uint32
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
}

// New returns a Collector that tracks nothing until Rescan.
func New(cfg Config) *Collector {
	c := &Collector{
		cfg:     cfg,
		log:     cfg.Log,
		tracked: make(map[string]*entry),
		next:    1, // 0 is other
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
	c.tracked[cg.Path] = &entry{cg: cg, id: id, idx: idx}
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
		c.collectHist(ch, e.idx, labelValues(e.cg))
	}
	c.collectHist(ch, Other, []string{"", "", OtherCgroup})
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

func (c *Collector) collectHist(ch chan<- prometheus.Metric, idx uint32, lv []string) {
	h, err := c.cfg.Store.Hist(idx)
	if err != nil {
		c.scanError(OpRead, fmt.Sprint(lv), err)
		return
	}
	count, buckets := h.Buckets(c.cfg.Slots)
	ch <- prometheus.MustNewConstHistogram(latencyDesc, count, float64(h.SumNS)/1e9, buckets, lv...)
}

// Buckets returns the histogram's count and its cumulative buckets by upper
// bound in seconds, as a Prometheus histogram, for the slots given (nil: all;
// see BucketSlots). The last slot is only in the count, which is the +Inf
// bucket. Leaving out a slot's bound merges it into the next exported bucket,
// which a cumulative histogram allows.
func (h *Hist) Buckets(slots []int) (uint64, map[float64]uint64) {
	cum := make([]uint64, MaxSlots)
	var n uint64
	for k := range MaxSlots {
		n += h.Slots[k]
		cum[k] = n
	}
	if slots == nil {
		slots = allSlots
	}
	buckets := make(map[float64]uint64, len(slots))
	for _, k := range slots {
		if k >= 0 && k < MaxSlots-1 {
			buckets[Upper(k)] = cum[k]
		}
	}
	return n, buckets
}

var allSlots = func() []int {
	s := make([]int, MaxSlots-1)
	for k := range s {
		s[k] = k
	}
	return s
}()

// MinBucket and MaxBucket are the smallest and largest finite bucket bounds the
// program's slots can give: 2 us and 2^23 us (about 8.4 s).
const (
	MinBucket = 2 * time.Microsecond
	MaxBucket = (1 << (MaxSlots - 1)) * time.Microsecond
)

// BucketSlots returns the slots whose upper bounds are min, min*factor,
// min*factor^2, ... max: the buckets to export. min and max must be powers of
// two microseconds within MinBucket..MaxBucket, factor a power of two, and max
// a power of factor times min. Fewer buckets mean fewer series (one a bucket
// and cgroup) and quantiles interpolated over a wider range.
func BucketSlots(min, max time.Duration, factor int) ([]int, error) {
	lo, ok := log2US(min)
	if !ok {
		return nil, fmt.Errorf("bucket minimum %s is not a power of two microseconds between %s and %s", min, MinBucket, MaxBucket)
	}
	hi, ok := log2US(max)
	if !ok {
		return nil, fmt.Errorf("bucket maximum %s is not a power of two microseconds between %s and %s", max, MinBucket, MaxBucket)
	}
	if hi < lo {
		return nil, fmt.Errorf("bucket maximum %s is below the minimum %s", max, min)
	}
	step := bits.TrailingZeros(uint(factor))
	if factor < 2 || factor&(factor-1) != 0 {
		return nil, fmt.Errorf("bucket factor %d is not a power of two of at least 2", factor)
	}
	if (hi-lo)%step != 0 {
		return nil, fmt.Errorf("bucket maximum %s is not %s times a power of %d", max, min, factor)
	}
	var slots []int
	for j := lo; j <= hi; j += step {
		slots = append(slots, j-1) // slot k's bound is 2^(k+1) us
	}
	return slots, nil
}

// log2US returns j for d = 2^j us with 1 <= j <= MaxSlots-1.
func log2US(d time.Duration) (int, bool) {
	if d < MinBucket || d > MaxBucket || d%time.Microsecond != 0 {
		return 0, false
	}
	us := uint64(d / time.Microsecond)
	if us&(us-1) != 0 {
		return 0, false
	}
	return bits.TrailingZeros64(us), true
}

func labelValues(cg cgroupfs.Cgroup) []string {
	return []string{cg.PodUID, cg.QoS, cg.Service}
}
