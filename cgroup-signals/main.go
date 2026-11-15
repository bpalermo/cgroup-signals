// Command cgroup-signals exports per-cgroup kernel signals (memory peak, PSI
// pressure events, run-queue latency) as Prometheus metrics. This is the
// skeleton: flags, /metrics, /healthz and graceful shutdown; the signals are
// added on top (see AGENTS.md).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/bpalermo/cgroup-signals/cgroup-signals/internal/server"
	"github.com/bpalermo/cgroup-signals/common/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "cgroup-signals:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("cgroup-signals", flag.ContinueOnError)
	var (
		listen      = fs.String("listen", ":9102", "address of the /metrics and /healthz endpoint")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn or error")
		showVersion = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid -log-level %q: %w", *logLevel, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	log.Info("starting", "version", version.Version)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewBuildInfoCollector(),
	)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, listener, server.Handler(reg), log)
}
