// Package server is the HTTP endpoint of cgroup-signals: /metrics in the
// Prometheus text format and /healthz for the kubelet's probes.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// shutdownTimeout bounds how long Run waits for in-flight requests once its
// context is done.
const shutdownTimeout = 10 * time.Second

// Handler serves /metrics from gatherer and /healthz.
func Handler(gatherer prometheus.Gatherer) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "ok")
	})
	return mux
}

// Run serves handler on listener until ctx is done, then shuts down
// gracefully. A clean shutdown returns nil.
func Run(ctx context.Context, listener net.Listener, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("serving", "address", listener.Addr().String())
		errc <- srv.Serve(listener)
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	// ctx is already done, so the shutdown gets its own deadline.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
