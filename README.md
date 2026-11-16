# cgroup-signals

cgroup-signals exports per-cgroup kernel signals as Prometheus metrics. It runs
as a privileged DaemonSet on cgroup v2 nodes (the target is a Talos cluster of
arm64 Raspberry Pi CM4 nodes). The signals:

- the memory peak of each pod's cgroup since the last scrape (`memory.peak`,
  read and reset through one file descriptor per cgroup);
- PSI pressure events (`cpu.pressure`, `memory.pressure` triggers, polled for
  `POLLPRI`);
- the `memory.events` counters (`high`, `max`, `oom_kill`, ...);
- a run-queue latency histogram per cgroup, from a CO-RE eBPF program on the
  `sched_wakeup` and `sched_switch` tracepoints. It is a separate mode,
  `--runqueue`, that runs as its own DaemonSet with its own, smaller set of
  privileges, and is off by default (see "Run-queue latency").

The kubelet's cAdvisor already exports each container's cumulative PSI
counters and lifetime `memory.peak`; cgroup-signals does not repeat them. What
it adds is what a 30-60 s scrape cannot see: a spike between two scrapes.

```bash
bazel run //cgroup-signals -- --version
bazel run //cgroup-signals -- --listen=:9102 --cgroup-root=/sys/fs/cgroup
```

## What it tracks

Every `--rescan-interval` it lists the kubelet's pod cgroups (cgroupfs driver,
the layout on Talos) and four node services, under `--cgroup-root`:

| Cgroup | Labels |
| --- | --- |
| `kubepods/pod<uid>` | `pod_uid`, `qos="guaranteed"` |
| `kubepods/burstable/pod<uid>` | `pod_uid`, `qos="burstable"` |
| `kubepods/besteffort/pod<uid>` | `pod_uid`, `qos="besteffort"` |
| `podruntime/kubelet`, `podruntime/runtime`, `system`, `init` | `cgroup="kubelet"`, `"runtime"`, `"system"`, `"init"` |

Pods are tracked at the pod level, not per container. `pod_uid` is the dashed
form of the pod's `metadata.uid` (the kubelet may write it with underscores).
Every per-cgroup series carries all three labels, the ones that do not apply
empty, and Prometheus drops empty labels on ingestion. A static pod's cgroup
is named after its manifest hash, which is not the UID of its mirror pod, so
static pods do not join `kube_pod_info`. The systemd cgroup driver's layout
(`kubepods.slice/...`) is not recognised.

For each tracked cgroup it holds three file descriptors: `memory.peak`, and a
PSI trigger on each of `cpu.pressure` and `memory.pressure`. A cgroup that
disappears (the next rescan does not find it, a read fails with `ENODEV`, or
its trigger polls `EPOLLERR`) is dropped and its descriptors closed, quietly:
that is not an error. `--max-tracked-cgroups` caps the count.

There is no Kubernetes API client. Join on `pod_uid` to kube-state-metrics'
`kube_pod_info{uid}` for the namespace, pod name and node:

```promql
cgroup_signals_memory_peak_bytes
  * on (pod_uid) group_left (namespace, pod)
    label_replace(kube_pod_info, "pod_uid", "$1", "uid", "(.+)")
```

## Metrics

| Metric | Type | Labels | |
| --- | --- | --- | --- |
| `cgroup_signals_memory_peak_bytes` | gauge | `pod_uid`, `qos`, `cgroup` | peak memory usage of the cgroup and its descendants since the previous scrape |
| `cgroup_signals_memory_events_total` | counter | `event`, `pod_uid`, `qos`, `cgroup` | `memory.events`: `event` is `low`, `high`, `max`, `oom`, `oom_kill` or `oom_group_kill` |
| `cgroup_signals_psi_trigger_events_total` | counter | `resource`, `pod_uid`, `qos`, `cgroup` | PSI trigger events; `resource` is `cpu` or `memory` |
| `cgroup_signals_tracked_cgroups` | gauge | | cgroups being tracked |
| `cgroup_signals_psi_trigger_fds` | gauge | | open PSI trigger file descriptors (two per tracked cgroup) |
| `cgroup_signals_scan_errors_total` | counter | `op` | errors by operation: `discover`, `limit`, `peak_open`, `peak_read`, `peak_reset`, `memory_events`, `psi_arm` |

Plus the Go runtime, process and build-info collectors.

### Memory peak since the last scrape

Since Linux 6.12 a write to `memory.peak` resets the watermark seen through
that file descriptor to the cgroup's current usage
([cgroup-v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)).
cgroup-signals keeps one descriptor open per cgroup and, in the scrape itself,
reads it and then resets it. So each sample is the highest usage between the
previous scrape and this one, starting from the usage at the previous scrape.
The first window starts when the cgroup is first tracked (the descriptor is
reset when it is opened; until then it would read the lifetime peak).

**One collector owns the reset.** Every scrape of `/metrics` resets, so two
Prometheus servers (or a person with curl) scraping the same instance split
the window between them, and each sees only the peaks since the other's last
scrape. The kernel also shares one "local" watermark between all descriptors
that ever reset a cgroup's `memory.peak`, so any other process that resets it
shortens this exporter's window too. Scrape each instance from one place.

On a kernel before 6.12 `memory.peak` cannot be opened for writing; the
gauge is then absent and `scan_errors_total{op="peak_open"}` counts the
cgroups.

### memory.events

Read at scrape time. The counters are cumulative since the cgroup was
created, and hierarchical: a pod's include its containers', and a QoS or
service cgroup's include everything under it. Use `increase()`/`rate()`.

### PSI triggers

Each tracked cgroup gets a trigger `some <threshold> <window>` on its
`cpu.pressure` and `memory.pressure`
([PSI](https://docs.kernel.org/accounting/psi.html)): the kernel signals
`POLLPRI` when the cgroup's tasks were stalled on the resource for at least
the threshold within a window, at most once per window. One goroutine waits
on all trigger descriptors with epoll. With the defaults (100 ms in 1 s) the
counter's increase is roughly the number of seconds in which some task of the
cgroup stalled for 100 ms or more.

The kernel's limits (`kernel/sched/psi.c`, 6.18): the window is at most 10 s;
the threshold is in (0, window]; and a writer without `CAP_SYS_RESOURCE` may
only use windows that are multiples of 2 s. cgroup-signals also refuses
windows under 500 ms (the kernel's documented floor until 6.4). It checks the
flags against its own capabilities at start.

A privileged trigger (any window, with `CAP_SYS_RESOURCE`) is polled by a
real-time `psimon` kernel thread, one per cgroup that has such triggers, that
wakes every window/10 while the cgroup is stalled. An unprivileged one (2 s
multiples) rides the 2 s averaging work instead and needs no thread.

## Flags

| Flag | Default | |
| --- | --- | --- |
| `--listen` | `:9102` | address of `/metrics` and `/healthz` |
| `--cgroup-root` | `/sys/fs/cgroup` | the cgroup v2 root; the DaemonSet passes `/host/sys/fs/cgroup` |
| `--rescan-interval` | `15s` | how often to rescan the cgroup tree |
| `--max-tracked-cgroups` | `512` | most cgroups tracked at once (three descriptors each; with `--runqueue`, one histogram each, at most 4095); `0` is no cap |
| `--runqueue` | off | run the run-queue latency exporter (eBPF) instead of the memory and PSI exporter; the PSI flags are then ignored, and `--cgroup-root` can be read-only |
| `--psi-threshold-us` | `100000` | PSI trigger stall threshold, in microseconds |
| `--psi-window-us` | `1000000` | PSI trigger window, in microseconds: 500 ms to 10 s, a multiple of 2 s without `CAP_SYS_RESOURCE` |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--version` | | print the version and exit |

## Privileges

It writes to the host's cgroupfs (the `memory.peak` resets and the PSI
triggers), so it needs:

- the host's `/sys/fs/cgroup` as a read-write `hostPath` volume, mounted at
  `--cgroup-root` (e.g. `/host/sys/fs/cgroup`); the hostPath shows the whole
  hierarchy whatever the container's cgroup namespace;
- uid 0, because the files are owned by root with mode 0644 (the image runs
  as uid 0), or `CAP_DAC_OVERRIDE`;
- `CAP_SYS_RESOURCE` for the default 1 s PSI window (any window that is not a
  multiple of 2 s);
- a namespace whose Pod Security level allows hostPath, i.e. `privileged`.

`privileged: true` covers all of it. Nothing else is needed: no host PID or
network namespace, and no Kubernetes API access.

## Run-queue latency

`cgroup-signals --runqueue` loads an eBPF program on the scheduler's
tracepoints and exports, per tracked cgroup, how long its tasks waited between
becoming runnable and getting on a CPU. That wait is what CPU pressure is made
of, and unlike PSI's averages it is a distribution: a few 5 ms waits and a
steady trickle of 50 us waits are different problems.

It is a different process from the default exporter on purpose. It runs
nothing of the memory-peak or PSI code, needs no write access to the cgroup
tree and none of that exporter's capabilities; the default exporter in turn
never gets `CAP_BPF`. Run it as its own DaemonSet (the chart's
`runqueue.enabled`), on another port (9103).

### Metric

| Metric | Type | Labels | |
| --- | --- | --- | --- |
| `cgroup_signals_runqueue_latency_seconds` | histogram | `pod_uid`, `qos`, `cgroup` | run-queue latency of the tasks of the cgroup and everything under it |
| `cgroup_signals_runqueue_tracked_cgroups` | gauge | | cgroups with a histogram, not counting `other` |
| `cgroup_signals_runqueue_missed_total` | counter | | switches to a task whose wakeup was not seen (already runnable when the program attached); not in the histograms |
| `cgroup_signals_runqueue_scan_errors_total` | counter | `op` | `discover`, `inode`, `limit`, `map`, `read` |

The histogram is a Prometheus **native histogram** of schema 0: one series per
cgroup, with buckets at powers of two seconds, (2^-20, 2^-19] s (about 1-1.9
us) to (2048, 4096] s. The program's log2 slots are those buckets exactly,
upper bound included: it counts in units of 2^-20 s, not microseconds. Delays
up to 2^-19 s are in bucket -19, not the zero bucket (Prometheus's OTLP
ingestion drops the zero threshold, which would make them zero); everything
over 2048 s is in the last bucket. `_sum` is
exact. There are no classic `_bucket` series: the scraper must ask for the
protobuf format (Prometheus: `scrape_native_histograms: true`; an OpenTelemetry
Collector's prometheus receiver: the same key, which yields an exponential
histogram), and a Prometheus that remote-writes onwards needs
`send_native_histograms: true`. A scrape in the text format sees no buckets,
only the count and the sum. It is cumulative since the cgroup was
first tracked (read at scrape, nothing is reset, any number of scrapers can read
it). The labels are the other metrics': a pod is `pod_uid` and `qos`, a node
service (`kubelet`, `runtime`, `system`, `init`) is `cgroup`, and
`cgroup="other"` is everything else: the QoS cgroups' own tasks, the root,
kernel threads, anything past `--max-tracked-cgroups`.

A latency is counted in the cgroup of the task that was waiting, at the moment
it gets on the CPU, resolved to the nearest tracked ancestor: a container's
delay lands in its pod's histogram. A delay is counted when the task is woken
(`sched_wakeup`, `sched_wakeup_new`), and again when it is preempted while
still runnable (`sched_switch` with the task in `TASK_RUNNING`); a task that
blocks is counted from its next wakeup. The time a woken task spends before it
is picked is the run-queue latency; the time on the CPU is not.

```promql
# p99 run-queue latency of each pod over 5 minutes
histogram_quantile(0.99,
  sum by (pod_uid) (rate(cgroup_signals_runqueue_latency_seconds{pod_uid!=""}[5m])))

# where the node's run-queue delay lands: seconds of waiting per second
sum by (pod_uid, cgroup) (histogram_sum(rate(cgroup_signals_runqueue_latency_seconds[5m])))

# the share of wakeups that waited over 1 ms (2^-10 s, a bucket bound)
1 - histogram_fraction(0, 0.0009765625,
  sum by (pod_uid, cgroup) (rate(cgroup_signals_runqueue_latency_seconds[5m])))
```

### Requirements and privileges

- Linux 5.11 or later (maps are charged to the memory cgroup, not to
  `RLIMIT_MEMLOCK`), built with BTF: `/sys/kernel/btf/vmlinux` must be readable
  (it is, in a container, unless the runtime masks it), and the `sched_wakeup`,
  `sched_wakeup_new` and `sched_switch` BTF tracepoints must exist. Without them
  the process exits at start with an error that says which is missing.
- `CAP_BPF` and `CAP_PERFMON`, uid 0 (a container's capabilities are effective
  only for root). Not `privileged: true`, not `CAP_SYS_ADMIN`, not
  `CAP_SYS_RESOURCE`. The runtime's default seccomp profile admits `bpf(2)`
  with `CAP_BPF`.
- The host's `/sys/fs/cgroup`, read-only: it is listed, and each directory
  `stat`ed for its inode number, which is the cgroup's id in the kernel
  (on a 64-bit kernel).

### How it works, and what it costs

`sched_wakeup` and `sched_wakeup_new` store `ktime` in a hash map by thread id.
`sched_switch` first does the same for the task leaving the CPU if it is still
runnable, then looks up the incoming task's timestamp, deletes it, finds the
histogram of the task's cgroup (one or two hash lookups for a tracked cgroup or
a container it has resolved before; a walk up at most 8 parents the first time,
and every time for a task under no tracked cgroup) and adds the delay to a per-CPU log2 histogram: no atomic, no lock.
The loader reads and sums the per-CPU copies at scrape time.

Overhead, **estimated, not measured on a Pi**: on the order of a few hundred
nanoseconds per wakeup and per switch on a Cortex-A72 (a hash update or lookup
and a handful of loads each). At the tens of thousands of switches per second
of a busy 4-core node that is around a percent of one core, under 0.5% of the
node; it grows linearly with the switch rate, so a fork-heavy node is the one to
watch. Measure it on
your nodes with `sysctl kernel.bpf_stats_enabled=1` and `bpftool prog show`
(`run_time_ns / run_cnt` per program; `cgroup_signals`' own
`process_cpu_seconds_total` is the user-space half, one pass per scrape and one
`stat` per tracked cgroup per rescan). Memory, also an estimate: the maps hold
about 1.5 MB with the defaults (the wakeup table's 16384 entries dominate),
charged to the pod.

Limits: the first delays after start miss tasks that were already runnable;
`start` has 16384 slots, so a node with more simultaneously runnable threads
loses wakeups (`missed_total`); a pod that starts running between two
rescans (15 s) counts in `other` until the next rescan tracks it (its
containers, once it is tracked, count in its histogram from their first
switch).

## Example queries

Peak since the last scrape against the pod's memory limit:

```promql
(
  cgroup_signals_memory_peak_bytes{pod_uid!=""}
    * on (pod_uid) group_left (namespace, pod)
      label_replace(kube_pod_info, "pod_uid", "$1", "uid", "(.+)")
)
/ on (namespace, pod) group_left
  sum by (namespace, pod) (kube_pod_container_resource_limits{resource="memory", unit="byte"})
```

Cgroups whose PSI triggers fired in the last 5 minutes:

```promql
increase(cgroup_signals_psi_trigger_events_total[5m]) > 0
```

and the same by pod name:

```promql
increase(cgroup_signals_psi_trigger_events_total{pod_uid!=""}[5m])
  * on (pod_uid) group_left (namespace, pod)
    label_replace(kube_pod_info, "pod_uid", "$1", "uid", "(.+)")
> 0
```

## Image

`ghcr.io/bpalermo/cgroup-signals` (the exporter; the bpftrace debug image is
described under "Debug pod (bpftrace)") is a multi-arch image (`linux/arm64` and
`linux/amd64`) on a digest-pinned distroless static base. The `publish`
workflow pushes it from `main` as `dev` and `dev-<commit>`.

## Helm chart

The `publish` workflow also pushes a Helm chart to
`oci://ghcr.io/bpalermo/charts/cgroup-signals` (GHCR), after the image. Its
version is `0.1.0-dev.<commit time>.g<short commit>` for a commit of `main` (the
bare version for a tagged release), one per commit and never moved. The chart
pins the multi-arch image that the same commit pushed **by digest**, so a chart
version always runs the build it was made with. The publish job refuses to push
a chart whose version or pinned digest is not the commit's
(`bazel/verify-chart.sh`).

```bash
helm install cgroup-signals oci://ghcr.io/bpalermo/charts/cgroup-signals \
  --version 0.1.0-dev.<commit time>.g<short commit> -n <ns>
```

It renders one DaemonSet and nothing else: no Service, ServiceMonitor,
ServiceAccount or RBAC (there is no API client, so no token is mounted).
Scrape the pods by their port name (`metrics`, `9102`), e.g. a Prometheus
`kubernetes_sd_configs` `role: pod` that keeps the container port named
`metrics`.

- **The namespace must allow `hostPath` and uid 0**: Pod Security `privileged`
  (baseline refuses `hostPath`). The pod mounts the host's `/sys/fs/cgroup`
  read-write at `/host/sys/fs/cgroup`, because the `memory.peak` resets and the
  PSI triggers are writes. It runs as uid 0 because the cgroup files are
  root-owned, mode 0644, with `allowPrivilegeEscalation: false`, a read-only
  root filesystem and every capability dropped. `CAP_SYS_RESOURCE` is not
  needed: the chart's default PSI window is 2 s.
- `privileged: true` adds `privileged: true` to the container. It is needed
  only for a `psi.windowUs` that is not a multiple of 2 s (2000000); without it
  such a value fails the render.
- **One scraper owns the reset.** Every `GET /metrics` resets each cgroup's
  `memory.peak`, so a scrape returns the peak since the *previous* scrape. A
  second scraper (another Prometheus, a `curl`, a health check) steals peaks
  from the first and leaves both with gaps. Scrape it from one place only.
- The probes use `/healthz`, never `/metrics`, for the same reason.
- **`runqueue.enabled`** adds the run-queue exporter as a second DaemonSet,
  `<release>-cgroup-signals-runqueue` (`app.kubernetes.io/name:
  cgroup-signals-runqueue`, so neither DaemonSet's selector matches the other's
  pods), off by default: with it off the chart renders exactly what it did
  before. Its container runs the same image with `--runqueue`, capabilities
  `drop: [ALL]` and `add: [BPF, PERFMON]`, no `privileged`, the host's
  `/sys/fs/cgroup` mounted **read-only**, probes on `/healthz`, and the port
  `runqueue` (9103). The namespace must allow hostPath and added capabilities
  (Pod Security `privileged`). It shares the top-level `image`, `nodeSelector`,
  `tolerations`, `priorityClassName`, `podLabels` and the rest; its own values
  are under `runqueue.` (`port`, `rescanInterval`, `maxTrackedCgroups`,
  `logLevel`, `extraArgs`, `resources`, `seccompProfile`, probes).
- Values (`chart/cgroup-signals/values.yaml`): `port`, `psi.thresholdUs`,
  `psi.windowUs`, `rescanInterval`, `maxTrackedCgroups`, `logLevel`,
  `extraArgs`, `privileged`, `resources` (10m / 32Mi requests, 96Mi memory
  limit), `priorityClassName`, `nodeSelector`, `affinity`, `tolerations`
  (default: every node), `podAnnotations`, `podLabels`, `image.tag` (an
  override of the digest, for trying a build), and `runqueue.*` (above).

## Debug pod (bpftrace)

For hunting a spike on one node there is a second image and chart, separate
from the exporter: `ghcr.io/bpalermo/cgroup-signals-bpftrace` and
`oci://ghcr.io/bpalermo/charts/bpftrace-debug`, published by the same
`publish` workflow, the chart pinning the image by digest like the other one.
The chart renders **one Pod** (not a DaemonSet) bound to the node you name. It
is for the length of an investigation: it is killed after
`activeDeadlineSeconds` (default 3600) whatever it is doing.

```bash
kubectl create namespace bpftrace-debug
kubectl label namespace bpftrace-debug pod-security.kubernetes.io/enforce=privileged

# Sleeps until the deadline, for `kubectl exec`:
helm install dbg oci://ghcr.io/bpalermo/charts/bpftrace-debug \
  --version 0.1.0-dev.<commit time>.g<short commit> -n bpftrace-debug --set node=main-worker-02
kubectl -n bpftrace-debug exec -it dbg-bpftrace-debug -- /busybox/sh
#   inside: bpftrace -e '...'   (examples below), bpftool prog show, bpftrace -l 'tracepoint:sched:*'

# Or run one program and let the pod complete (read it with `kubectl logs`):
helm install dbg oci://ghcr.io/bpalermo/charts/bpftrace-debug -n bpftrace-debug \
  --set node=main-worker-02 --set-file programFile=./spike.bt          # or --set-string program='...'

helm uninstall dbg -n bpftrace-debug
```

- **The namespace must be Pod Security `privileged`**: the pod is `privileged`,
  uid 0, `hostPID`, with hostPath mounts. On Talos bpftrace is not a
  capability-only job (tracefs and debugfs writes, kprobe and uprobe
  registration and other processes' `/proc` want `CAP_SYS_ADMIN`, and the
  default seccomp and LSM policy still stand in the way), so this chart does
  not pretend to be less than privileged. Everything else is closed: no API
  token, no service links, no host network or IPC, `restartPolicy: Never`.
- `node` is **required** (the render fails without it): `spec.nodeName`, so the
  scheduler, taints and cordons are bypassed. Mounted from the host:
  `/sys/kernel/debug` and `/sys/kernel/tracing` (read-write), `/sys/kernel/btf`,
  `/sys/fs/cgroup` and `/lib/modules` (read-only). The host's processes are
  visible through `hostPID`. `/sys/kernel/debug` and `/lib/modules` have no
  hostPath type, so a node without them still starts the pod.
- Values: `node`, `program` (`bpftrace -e`), `programFile` (a ConfigMap the
  chart renders; not both), `args` (flags before the program),
  `activeDeadlineSeconds`, `terminationGracePeriodSeconds` (5),
  `resources` (100m / 256Mi requests, **1Gi memory limit**: bpftrace compiles
  with LLVM in-process and can need a few hundred MiB while it does),
  `priorityClassName`, `tolerations` (every node), `podLabels`,
  `podAnnotations`, `image.tag`.

### The image

A multi-arch index (`linux/arm64`, `linux/amd64`) on
`gcr.io/distroless/static-debian13:debug`, pinned by digest: a shell
(`/busybox/sh`) to exec into, and nothing else a package manager would bring.
Inside, at `/usr/local/bin`: **bpftrace v0.27.1** and **bpftool v7.8.1**
(libbpf's static release binaries), plus bpftrace's upstream tools at
`/usr/share/bpftrace/tools`.

The upstream `bpftrace-aarch64` / `bpftrace-x86_64` assets are **not static
binaries**: they are Nix-built AppImages (a static runtime and a squashfs of
bpftrace with libLLVM, libclang and glibc under `/nix/store`) that need FUSE or
a user namespace to start, and a user namespace has no `CAP_BPF` in the host's.
So the build unpacks them (`//appimage-closure`, a pure-Go squashfs reader that
follows the program's `RUNPATH`s the way ld.so does) and the image holds the
program and the libraries it loads at `/nix/store`, where its interpreter
expects them. No FUSE, no namespace, no extraction at start-up. The image is
about 430 MiB uncompressed per architecture (LLVM is most of it); the assets
are pinned by the sha256 GitHub records for the release.

### One-liners for spike hunting

Run them inside the pod (`bpftrace -e '...'`, Ctrl-C prints the maps). Each of
these parses, type-checks and compiles with the image's bpftrace 0.27.1
(`bpftrace --dry-run`, against a 6.8 BTF and tracepoint formats written from
the 6.18 sources, not read from a node); the kernel's verifier has not seen
them, and none has run on a node. `bpftrace -l '<pattern>'` lists what your kernel has if one is
refused. Output is per second or per 10 s where a `interval` probe says so.

**Run-queue latency histogram (microseconds from wakeup, or from an
involuntary preemption, to running again; the idle task is excluded):**

```
bpftrace -e '
tracepoint:sched:sched_wakeup, tracepoint:sched:sched_wakeup_new { @qtime[args->pid] = nsecs; }
tracepoint:sched:sched_switch {
  if (args->prev_pid != 0 && (args->prev_state & 0x100)) { @qtime[args->prev_pid] = nsecs; }
  $ns = @qtime[args->next_pid];
  if (args->next_pid != 0 && $ns) { @runq_us = hist((uint64)(nsecs - (uint64)$ns) / 1000); }
  delete(@qtime[args->next_pid]);
}
'
```

**Who is being preempted while the CPU is contended** (`prev_state & 0x100` is
`TASK_REPORT_MAX`, which the tracepoint sets on a task switched out while still
runnable, that is preempted; the idle task is excluded; the pair is preempted,
preemptor):

```
bpftrace -e '
tracepoint:sched:sched_switch /args->prev_pid != 0 && (args->prev_state & 0x100)/ { @preempted[args->prev_comm, args->next_comm] = count(); }
interval:s:10 { print(@preempted, 20); clear(@preempted); }
'
```

**Off-CPU time by cgroup** (milliseconds slept or blocked, per 10 s, charged
to the cgroup the task left the CPU from, saved at switch-out and read back at
switch-in; preempted tasks are not counted; the cgroup path tells the pod from
the kubelet or containerd):

```
bpftrace -e '
tracepoint:sched:sched_switch {
  if (args->prev_pid != 0 && (args->prev_state & 0xff)) { @start[args->prev_pid] = nsecs; @cg[args->prev_pid] = cgroup_path(cgroup); }
  $s = @start[args->next_pid];
  if (args->next_pid != 0 && $s) { @offcpu_ms[@cg[args->next_pid]] = sum((uint64)(nsecs - (uint64)$s) / 1000000); }
  delete(@start[args->next_pid]);
  delete(@cg[args->next_pid]);
}
interval:s:10 { print(@offcpu_ms, 15); clear(@offcpu_ms); }
'
```

**Direct reclaim and `memory.high` throttling stalls** (a task reclaiming
itself before it can allocate, and the time `mem_cgroup_handle_over_high`
holds a task back when its cgroup is over `memory.high`; both per command):

```
bpftrace -e '
tracepoint:vmscan:mm_vmscan_direct_reclaim_begin { @t[tid] = nsecs; }
tracepoint:vmscan:mm_vmscan_direct_reclaim_end /@t[tid]/ { @reclaim_us[comm] = hist((uint64)(nsecs - (uint64)@t[tid]) / 1000); delete(@t[tid]); }
kprobe:mem_cgroup_handle_over_high { @h[tid] = nsecs; }
kretprobe:mem_cgroup_handle_over_high /@h[tid]/ { @high_throttle_us[comm] = hist((uint64)(nsecs - (uint64)@h[tid]) / 1000); delete(@h[tid]); }
'
```

**Page faults by cgroup** (the software event, because the
`exceptions:page_fault_*` tracepoints exist on x86 only):

```
bpftrace -e '
software:page-faults:1 { @faults[cgroup_path(cgroup)] = count(); }
interval:s:10 { print(@faults, 15); clear(@faults); }
'
```

**kubelet, containerd and etcd CPU bursts** (on-CPU samples at 99 Hz, printed
every second: a burst shows as a second above the baseline of about 99 samples
per busy core):

```
bpftrace -e '
profile:hz:99 /comm == "kubelet" || comm == "containerd" || comm == "etcd"/ { @samples[comm] = count(); }
interval:s:1 { print(@samples); clear(@samples); }
'
```

Pair a burst with the metrics of this exporter: the run-queue histogram says
*that* tasks waited, these say *who* and *where*.

## Development

Bazel is the only build; see [AGENTS.md](AGENTS.md).

```bash
bazel test //...
bazel run //:gazelle
bazel run //:format
```

## License

Apache-2.0, see [LICENSE](LICENSE).
