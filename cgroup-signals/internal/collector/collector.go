// Package collector tracks the pod and node-service cgroups and exports their
// signals: the memory peak since the previous scrape, memory.events, and the
// PSI trigger events.
//
// The memory peak is read and reset in Collect, not in a background loop, so
// its window is exactly the time between two scrapes.
package collector

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/cgroupfs"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/peak"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/psi"
)

const namespace = "cgroup_signals"

// cgroupLabels are on every per-cgroup series. A pod's series have pod_uid
// and qos and an empty cgroup; a node service's have cgroup only. Prometheus
// drops empty labels on ingestion, so each reads as having only its own.
var cgroupLabels = []string{"pod_uid", "qos", "cgroup"}

// The scan_errors_total{op} values.
const (
	OpDiscover     = "discover"
	OpLimit        = "limit"
	OpPeakOpen     = "peak_open"
	OpPeakRead     = "peak_read"
	OpPeakReset    = "peak_reset"
	OpMemoryEvents = "memory_events"
	OpPSIArm       = "psi_arm"
)

var ops = []string{OpDiscover, OpLimit, OpPeakOpen, OpPeakRead, OpPeakReset, OpMemoryEvents, OpPSIArm}

var (
	peakDesc = prometheus.NewDesc(namespace+"_memory_peak_bytes",
		"Peak memory usage of the cgroup and its descendants since the previous scrape: memory.peak, read and then reset "+
			"through this exporter's own file descriptor at each scrape. One collector owns the reset: two scrapers "+
			"(or anything else resetting memory.peak) split the window between them.",
		cgroupLabels, nil)
	eventsDesc = prometheus.NewDesc(namespace+"_memory_events_total",
		"memory.events counters of the cgroup. Cumulative since the cgroup was created, and hierarchical: they include "+
			"the events of descendant cgroups.",
		append([]string{"event"}, cgroupLabels...), nil)
	trackedDesc = prometheus.NewDesc(namespace+"_tracked_cgroups",
		"Cgroups being tracked (pods and node services).", nil, nil)
	triggerFDsDesc = prometheus.NewDesc(namespace+"_psi_trigger_fds",
		"Open PSI trigger file descriptors (two per tracked cgroup when every trigger is armed).", nil, nil)
)

// PSI arms and removes the PSI triggers of a cgroup; *psi.Watcher is one.
type PSI interface {
	Watch(key string, res psi.Resource, path string) error
	Remove(key string)
	Len() int
}

// Config is what New needs.
type Config struct {
	// Root is the cgroup v2 root on disk: the PSI triggers and memory.peak
	// are opened under it.
	Root string
	// FS is the same root as an fs.FS, for discovery and memory.events;
	// os.DirFS(Root) if nil.
	FS fs.FS
	// Peaks opens memory.peak; peak.OSOpener if nil.
	Peaks peak.Opener
	// PSI arms the triggers. Set it with SetPSI if it needs the Collector
	// as its handler.
	PSI PSI
	// MaxTracked caps the tracked cgroups, and with them the open file
	// descriptors (three each). Zero is no cap.
	MaxTracked int
	Log        *slog.Logger
}

type entry struct {
	cg   cgroupfs.Cgroup
	peak *peak.Reader // nil if memory.peak could not be opened
}

// Collector is a prometheus.Collector over the tracked cgroups. It is also
// the psi.Handler of the Watcher.
type Collector struct {
	root       string
	fsys       fs.FS
	peaks      peak.Opener
	maxTracked int
	log        *slog.Logger

	psiEvents  *prometheus.CounterVec
	scanErrors *prometheus.CounterVec

	// mu guards tracked and psi, and serializes Collect: the peak reset
	// makes a scrape stateful.
	mu      sync.Mutex
	psi     PSI
	tracked map[string]*entry // by cgroupfs.Cgroup.Path
}

// New returns a Collector that tracks nothing until Rescan.
func New(cfg Config) *Collector {
	c := &Collector{
		root:       cfg.Root,
		fsys:       cfg.FS,
		peaks:      cfg.Peaks,
		maxTracked: cfg.MaxTracked,
		log:        cfg.Log,
		psi:        cfg.PSI,
		tracked:    make(map[string]*entry),
		psiEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "psi_trigger_events_total",
			Help:      "PSI trigger events: the cgroup's tasks stalled on the resource (\"some\") for at least the threshold within the window.",
		}, append([]string{"resource"}, cgroupLabels...)),
		scanErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "scan_errors_total",
			Help:      "Errors tracking or reading cgroups, by operation. A cgroup that disappears is not an error.",
		}, []string{"op"}),
	}
	if c.fsys == nil {
		c.fsys = os.DirFS(c.root)
	}
	if c.peaks == nil {
		c.peaks = peak.OSOpener{}
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	for _, op := range ops {
		c.scanErrors.WithLabelValues(op)
	}
	return c
}

// SetPSI sets the PSI triggers' owner. Call it before the first Rescan.
func (c *Collector) SetPSI(p PSI) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.psi = p
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

// Rescan discovers the cgroups, tracks the new ones and drops the ones that
// are gone. After a discovery error nothing is dropped, so a transient error
// cannot reset every window.
func (c *Collector) Rescan() {
	found, err := cgroupfs.Discover(c.fsys)
	if err != nil {
		c.scanError(OpDiscover, "", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[string]bool, len(found))
	for _, cg := range found {
		seen[cg.Path] = true
		if c.tracked[cg.Path] == nil {
			c.track(cg)
		}
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

// track opens everything held for cg. Called with mu held.
func (c *Collector) track(cg cgroupfs.Cgroup) {
	if c.maxTracked > 0 && len(c.tracked) >= c.maxTracked {
		c.scanError(OpLimit, cg.Path, errors.New("too many cgroups"))
		return
	}
	e := &entry{cg: cg}
	c.tracked[cg.Path] = e
	dir := filepath.Join(c.root, filepath.FromSlash(cg.Path))

	r, err := peak.Open(c.peaks, filepath.Join(dir, "memory.peak"))
	if err == nil {
		e.peak = r
	} else if !c.failed(cg.Path, OpPeakOpen, err) {
		return
	}
	lv := labelValues(cg)
	for _, res := range psi.Resources {
		// Present from the start, so that increase() sees the first event.
		c.psiEvents.WithLabelValues(append([]string{string(res)}, lv...)...)
		if c.psi == nil {
			continue
		}
		if err := c.psi.Watch(cg.Path, res, filepath.Join(dir, res.File())); err != nil && !c.failed(cg.Path, OpPSIArm, err) {
			return
		}
	}
	c.log.Debug("tracking cgroup", "path", cg.Path)
}

// drop closes everything held for the cgroup at p. Called with mu held.
func (c *Collector) drop(p, why string) {
	e := c.tracked[p]
	if e == nil {
		return
	}
	delete(c.tracked, p)
	if e.peak != nil {
		_ = e.peak.Close()
	}
	if c.psi != nil {
		c.psi.Remove(p)
	}
	lv := labelValues(e.cg)
	c.psiEvents.DeletePartialMatch(prometheus.Labels{"pod_uid": lv[0], "qos": lv[1], "cgroup": lv[2]})
	c.log.Debug("dropped cgroup", "path", p, "reason", why)
}

// failed handles err from operation op on the cgroup at p. If the cgroup was
// removed, it drops the cgroup quietly and returns false; otherwise it counts
// the error and returns true (the cgroup stays tracked). Called with mu held.
func (c *Collector) failed(p, op string, err error) bool {
	if c.removed(p, err) {
		c.drop(p, op+" on a removed cgroup")
		return false
	}
	c.scanError(op, p, err)
	return true
}

// removed reports whether err, or the cgroup's directory being gone, says
// the cgroup at p was removed.
func (c *Collector) removed(p string, err error) bool {
	if cgroupfs.IsRemoved(err) {
		return true
	}
	_, statErr := fs.Stat(c.fsys, p)
	return errors.Is(statErr, fs.ErrNotExist)
}

func (c *Collector) scanError(op, p string, err error) {
	c.scanErrors.WithLabelValues(op).Inc()
	c.log.Warn("scan error", "op", op, "path", p, "err", err)
}

// Event implements psi.Handler.
func (c *Collector) Event(key string, res psi.Resource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.tracked[key]
	if e == nil {
		return // dropped since; do not bring its series back
	}
	c.psiEvents.WithLabelValues(append([]string{string(res)}, labelValues(e.cg)...)...).Inc()
}

// Gone implements psi.Handler.
func (c *Collector) Gone(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drop(key, "PSI trigger reported the cgroup removed")
}

// Close drops every tracked cgroup.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.tracked {
		c.drop(p, "shutdown")
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- peakDesc
	ch <- eventsDesc
	ch <- trackedDesc
	ch <- triggerFDsDesc
	c.psiEvents.Describe(ch)
	c.scanErrors.Describe(ch)
}

// Collect implements prometheus.Collector. It reads and resets each tracked
// cgroup's memory.peak and reads its memory.events.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, e := range c.tracked {
		if c.collectPeak(ch, p, e) {
			c.collectEvents(ch, p, e)
		}
	}
	ch <- prometheus.MustNewConstMetric(trackedDesc, prometheus.GaugeValue, float64(len(c.tracked)))
	fds := 0
	if c.psi != nil {
		fds = c.psi.Len()
	}
	ch <- prometheus.MustNewConstMetric(triggerFDsDesc, prometheus.GaugeValue, float64(fds))
	c.psiEvents.Collect(ch)
	c.scanErrors.Collect(ch)
}

// collectPeak returns false if the cgroup was dropped.
func (c *Collector) collectPeak(ch chan<- prometheus.Metric, p string, e *entry) bool {
	if e.peak == nil {
		return true
	}
	v, err := e.peak.Read()
	if err != nil {
		return c.failed(p, OpPeakRead, err)
	}
	ch <- prometheus.MustNewConstMetric(peakDesc, prometheus.GaugeValue, float64(v), labelValues(e.cg)...)
	if err := e.peak.Reset(); err != nil {
		return c.failed(p, OpPeakReset, err)
	}
	return true
}

func (c *Collector) collectEvents(ch chan<- prometheus.Metric, p string, e *entry) {
	data, err := fs.ReadFile(c.fsys, path.Join(p, "memory.events"))
	if err != nil {
		c.failed(p, OpMemoryEvents, err)
		return
	}
	values, err := cgroupfs.ParseFlatKeyed(data)
	if err != nil {
		c.scanError(OpMemoryEvents, p, err)
		return
	}
	lv := labelValues(e.cg)
	for _, name := range cgroupfs.MemoryEventNames {
		if v, ok := values[name]; ok {
			ch <- prometheus.MustNewConstMetric(eventsDesc, prometheus.CounterValue, float64(v), append([]string{name}, lv...)...)
		}
	}
}

func labelValues(cg cgroupfs.Cgroup) []string {
	return []string{cg.PodUID, cg.QoS, cg.Service}
}
