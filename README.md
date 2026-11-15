# cgroup-signals

cgroup-signals exports per-cgroup kernel signals as Prometheus metrics. It runs
as a privileged DaemonSet on cgroup v2 nodes (the target is a Talos cluster of
arm64 Raspberry Pi CM4 nodes) and is meant to grow three signals:

- the memory peak of each pod's cgroup since the last scrape (`memory.peak`,
  read and reset through one file descriptor per cgroup);
- PSI pressure events (`cpu.pressure`, `memory.pressure` triggers, polled for
  `POLLPRI`);
- a run-queue latency histogram per cgroup, from a CO-RE eBPF program on the
  `sched_wakeup` and `sched_switch` tracepoints.

This is the skeleton: the binary serves `/metrics` (Go runtime, process and
build metrics) and `/healthz`, and shuts down gracefully. The signals are not
implemented yet.

```bash
bazel run //cgroup-signals -- --version
bazel run //cgroup-signals -- --listen=:9102
```

| Flag | Default | |
| --- | --- | --- |
| `--listen` | `:9102` | address of `/metrics` and `/healthz` |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--version` | | print the version and exit |

## Image

`ghcr.io/bpalermo/cgroup-signals` is a multi-arch image (`linux/arm64` and
`linux/amd64`) on a digest-pinned distroless static base. The `publish`
workflow pushes it from `main` as `dev` and `dev-<commit>`.

## Development

Bazel is the only build; see [AGENTS.md](AGENTS.md).

```bash
bazel test //...
bazel run //:gazelle
bazel run //:format
```

## License

Apache-2.0, see [LICENSE](LICENSE).
