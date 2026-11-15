// Command cgroup-signals exports per-cgroup kernel signals of the pod and
// node-service cgroups as Prometheus metrics: the memory peak since the
// previous scrape, memory.events, and PSI trigger events (see AGENTS.md).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/cgroupfs"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/collector"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/psi"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/server"
	"github.com/bpalermo/cgroup-signals/common/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "cgroup-signals:", err)
		os.Exit(1)
	}
}

type config struct {
	listen         string
	logLevel       slog.Level
	cgroupRoot     string
	rescanInterval time.Duration
	maxTracked     int
	trigger        psi.Trigger
}

// errVersion means --version was given and printed.
var errVersion = errors.New("version printed")

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("cgroup-signals", flag.ContinueOnError)
	var (
		cfg         config
		logLevel    string
		thresholdUS uint
		windowUS    uint
		showVersion bool
	)
	fs.StringVar(&cfg.listen, "listen", ":9102", "address of the /metrics and /healthz endpoint")
	fs.StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn or error")
	fs.StringVar(&cfg.cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "the cgroup v2 root, mounted read-write")
	fs.DurationVar(&cfg.rescanInterval, "rescan-interval", 15*time.Second, "how often to rescan the cgroup tree")
	fs.IntVar(&cfg.maxTracked, "max-tracked-cgroups", 512, "most cgroups tracked at once, each holding three file descriptors (0: no cap)")
	fs.UintVar(&thresholdUS, "psi-threshold-us", 100000, "PSI trigger: stall time within the window, in microseconds, that raises an event")
	fs.UintVar(&windowUS, "psi-window-us", 1000000, "PSI trigger: window in microseconds; a multiple of 2 s unless the process has CAP_SYS_RESOURCE")
	fs.BoolVar(&showVersion, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if showVersion {
		fmt.Println(version.Version)
		return cfg, errVersion
	}
	if err := cfg.logLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return cfg, fmt.Errorf("invalid -log-level %q: %w", logLevel, err)
	}
	if cfg.rescanInterval <= 0 {
		return cfg, fmt.Errorf("-rescan-interval must be positive, got %s", cfg.rescanInterval)
	}
	if thresholdUS > math.MaxUint32 || windowUS > math.MaxUint32 {
		return cfg, errors.New("-psi-threshold-us and -psi-window-us must fit in 32 bits")
	}
	cfg.trigger = psi.Trigger{ThresholdUS: uint32(thresholdUS), WindowUS: uint32(windowUS)}
	return cfg, validateTrigger(cfg.trigger)
}

// validateTrigger checks the trigger against the kernel's limits for this
// process's capabilities, so a bad flag fails at start rather than as an
// EINVAL on every cgroup.
func validateTrigger(t psi.Trigger) error {
	privileged, err := psi.Privileged()
	if err != nil {
		return err
	}
	return t.Validate(privileged)
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if errors.Is(err, errVersion) {
		return nil
	}
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.logLevel}))
	log.Info("starting", "version", version.Version, "cgroup_root", cfg.cgroupRoot, "psi_trigger", cfg.trigger.String())

	if err := cgroupfs.CheckV2(cfg.cgroupRoot); err != nil {
		return err
	}
	col := collector.New(collector.Config{Root: cfg.cgroupRoot, MaxTracked: cfg.maxTracked, Log: log})
	watcher, err := psi.NewWatcher(cfg.trigger, col)
	if err != nil {
		return err
	}
	col.SetPSI(watcher)
	col.Rescan()

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewBuildInfoCollector(),
		col,
	)

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		col.Close()
		return errors.Join(err, watcher.Close())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, col, watcher, listener, reg, log)
}

// serve runs the rescan loop, the PSI loop and the HTTP server until ctx is
// done or one of them fails, then closes every cgroup file.
func serve(ctx context.Context, cfg config, col *collector.Collector, watcher *psi.Watcher,
	listener net.Listener, reg *prometheus.Registry, log *slog.Logger,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	fail := func(err error) {
		if err != nil {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
			cancel()
		}
	}
	wg.Go(func() { col.Run(ctx, cfg.rescanInterval) })
	wg.Go(func() { fail(watcher.Run(ctx)) })
	wg.Go(func() { fail(server.Run(ctx, listener, server.Handler(reg), log)) })
	wg.Wait()
	col.Close()
	errs = append(errs, watcher.Close())
	return errors.Join(errs...)
}
