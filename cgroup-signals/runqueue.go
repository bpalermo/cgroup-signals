package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/cgroupfs"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/runqlat"
	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/server"
	"github.com/bpalermo/cgroup-signals/common/version"
)

// runRunqueue is the --runqueue mode: it loads the run-queue latency eBPF
// program and serves its histograms. It starts no PSI trigger and holds no
// memory.peak descriptor, so it needs only CAP_BPF and CAP_PERFMON and reads
// the cgroup tree.
func runRunqueue(cfg config, log *slog.Logger) error {
	log.Info("starting", "version", version.Version, "mode", "runqueue", "cgroup_root", cfg.cgroupRoot)
	if err := cgroupfs.CheckV2(cfg.cgroupRoot); err != nil {
		return err
	}
	limit := cfg.maxTracked
	if limit <= 0 || limit >= runqlat.MaxCgroups {
		limit = runqlat.MaxCgroups - 1
	}
	prog, err := runqlat.Load(limit)
	if err != nil {
		return err
	}
	defer func() {
		if err := prog.Close(); err != nil {
			log.Warn("closing the BPF program", "err", err)
		}
	}()

	col := runqlat.New(runqlat.Config{
		Store:      prog,
		Missed:     prog.Missed,
		FS:         os.DirFS(cfg.cgroupRoot),
		Inode:      func(p string) (uint64, error) { return cgroupfs.Inode(cfg.cgroupRoot, p) },
		MaxTracked: limit,
		Slots:      cfg.bucketSlots,
		Log:        log,
	})
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
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	wg.Go(func() { col.Run(ctx, cfg.rescanInterval) })
	wg.Go(func() {
		if err := server.Run(ctx, listener, server.Handler(reg), log); err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("serving: %w", err))
			mu.Unlock()
			cancel()
		}
	})
	wg.Wait()
	col.Close()
	return errors.Join(errs...)
}
