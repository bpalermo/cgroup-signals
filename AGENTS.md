# AGENTS.md

Guidance for agents working in this repository.

## What this is

cgroup-signals is one Go binary, `cgroup-signals`, plus an on-demand bpftrace
debug pod (see "Images and versions"). The binary runs as a privileged
DaemonSet on cgroup v2 nodes (Talos, kernel 6.18, arm64 Raspberry Pi CM4; amd64
is built too). It exports per-cgroup kernel signals as Prometheus metrics:

1. `memory.peak` of each pod and node-service cgroup, read through one fd per
   cgroup and reset by writing to that fd in every scrape (the peak since the
   last scrape; kernel 6.12+);
2. PSI triggers armed on `cpu.pressure` and `memory.pressure`, waited on for
   `POLLPRI` by one epoll goroutine;
3. the `memory.events` counters, read at scrape time;
4. a CO-RE eBPF run-queue latency histogram per cgroup (`sched_wakeup` and
   `sched_switch` tracepoints), in a separate mode of the same binary
   (`--runqueue`) that the chart runs as its own DaemonSet, off by default.

All four are implemented (README.md lists the metrics, flags and privileges).
`--runqueue` runs ONLY signal 4: none of the memory or PSI code, and none of
the capabilities those need; the default mode runs 1-3 and loads no BPF. Keep
it that way: the default exporter's no-capability security context is the
reason it is a separate pod. Keep this section true as the signals land.

Rules the code depends on:

- One collector owns the `memory.peak` reset, and it happens in `Collect`,
  never in a background loop: the window is the scrape interval.
- A cgroup that disappears (not found by the rescan, `ENODEV`, `EPOLLERR`) is
  dropped quietly and everything held for it closed; it is not a scan error.
- No Kubernetes API client: pods are identified by `pod_uid`, joined in
  PromQL to kube-state-metrics' `kube_pod_info{uid}`.
- Do not export what cAdvisor already does (per-container PSI totals,
  lifetime `memory.peak`).

## Build and test

```bash
bazel test //...            # builds and runs the unit tests
bazel build --config=ci //...   # what CI runs: also shellcheck, gocognit, lockfile check
bazel run //:gazelle        # after adding, removing or renaming any .go file
bazel run //:format         # format Starlark, Go and shell; CI runs //:format.check
bazel mod tidy              # after changing go.mod or a bazel_dep
bazel run //cgroup-signals -- --version
```

Bazel is the only build. Never run the host `go` tool (`go build`, `go vet`,
`go mod tidy`); change a dependency through rules_go's SDK:

```bash
bazel run @rules_go//go -- get github.com/some/module@v1.2.3
```

then `bazel mod tidy` and `bazel run //:gazelle`.

Linting is part of the build. Every Go package is compiled with the analyzers
of `//:nogo` (vet's and staticcheck's); a finding is a compile error. Shell
scripts are checked by shellcheck and Go functions by gocognit, both aspects
that `--config=ci` turns on. gocognit's threshold is 15 (`bazel/lint/linters.bzl`)
and is never raised. Production code only; tests are not visited.

CI runs with `--config=ci`, which fails if `MODULE.bazel.lock` is out of date
and requires that Gazelle leaves no diff.

A local `user.bazelrc` (untracked) points module fetches at the public Go
proxy, because the Go environment here is `GOPROXY=direct`.

## Layout

- No `cmd/`. The binary lives in a root-level directory with its `main.go`:
  `cgroup-signals/`. Code private to it is under its `internal/`; code shared
  between binaries goes under `common/`.
- `cgroup-signals/internal/`: `cgroupfs` (discovery and file parsing),
  `peak` (the per-fd `memory.peak` read and reset; `peak/peaktest` fakes the
  kernel's semantics), `psi` (trigger validation, arming, the epoll
  watcher), `collector` (the `prometheus.Collector` that owns the tracked
  cgroups), `runqlat` (the run-queue eBPF program: loader, histogram indices,
  its own `prometheus.Collector`) and `server` (HTTP). File access goes through `fs.FS` and small
  interfaces, so the logic is tested against a tree under `t.TempDir()`.
- `appimage-closure/`: the build tool that unpacks bpftrace's AppImage (not
  shipped; `internal/tree` reads the squashfs, `internal/closure` follows the
  ELF run paths and writes the tar). `bpftrace/` is the debug image's BUILD.
- `bpf/` holds the `*.bpf.c` programs, their headers and `vmlinux.h` (see BPF
  below); `bazel/bpf/` the rule that compiles them.
- `bazel/` holds build rules: `image/` (the `go_image` macro), `lint/`,
  `nogo/`, `format/`, `platforms/`, `registry.bzl`, the workspace status
  script and the CI target-determination script.

## BPF

One program so far: `bpf/runqlat.bpf.c`, the run-queue latency histogram
(adapted from libbpf-tools' `runqlat.bpf.c`; see `bpf/README.md` for the
licence). Go loads it with `github.com/cilium/ebpf` (pure Go, no cgo) from
`cgroup-signals/internal/runqlat`, which also assigns the histogram indices and
exports the Prometheus histogram.

How it works, because the C and the Go depend on each other:

- The program counts into `hists[idx]`, a per-CPU array of `struct hist`
  (`MAX_SLOTS` log2 slots in microseconds, plus the sum in ns). `idx` comes from
  the `tracked` map (cgroup id to index), which the loader fills from the
  cgroups it discovers; a task's cgroup is looked up, then its ancestors' up to
  `MAX_DEPTH`, and what is under none counts in index 0 ("other"). A
  container's resolution is remembered in the LRU map `below` (hits only).
  Each task also remembers its own: the enqueue time and the resolved index
  live in task local storage (`tasks`), valid while the task's cgroup id is the
  same and the `gen` array's value equals the one stored with it. The loader
  (`Program.SetTracked`/`DeleteTracked`) adds one to `gen` AFTER every change
  to `tracked`; the program reads `gen` BEFORE it resolves. Keep that order,
  or a reused index or a newly tracked cgroup is counted wrong
  (`TestCacheInvalidation`). `TestMeasure` (env `RUNQLAT_BENCH_OBJECT`) is the
  cost benchmark the `bpf-load` job runs on the base and head objects.
  `MAX_SLOTS` and `MAX_CGROUPS` are in `bpf/runqlat.h` and again in
  `runqlat.go`; `TestObject` fails if the struct sizes drift apart.
- The cgroup id is the inode number of the cgroup's directory (64-bit kernels),
  so the loader needs only to `stat` the directories it already discovers.
- An index is reused only one rescan after its cgroup was dropped
  (`quarantine`), and zeroed before it is handed out.
- Kernel structures are read by direct dereference, relocated by CO-RE through
  `bpf/vmlinux.h`, which is a hand-trimmed file, not bpftool's dump (see its
  header). Adding a field the program reads means adding it there AND to
  `runqlat.KernelHasFields`, which `TestKernelBTF` checks against the running
  kernel's BTF with no root.

### The compile path (decided: hermetic clang in Bazel)

`bazel/bpf/defs.bzl`'s `bpf_object` runs `@llvm_toolchain_llvm//:bin/clang`
(LLVM 20.1.8 from `toolchains_llvm`, whichever linux amd64 or arm64 release
matches the machine Bazel runs on) with `--target=bpfel -mcpu=v3 -O2 -g`, and
libbpf's headers from the `libbpf` BCR module. Nothing on the host is used; no
C++ toolchain is registered, so Go and everything else build as before. One
`bpfel` object serves arm64 and amd64 (both little-endian; CO-RE does the rest),
and `copy_file` puts it next to the Go code for `go:embed`. The object is built,
not checked in.

Why not `bpf2go` with checked-in objects: it needs a pinned clang on the
machine that runs `go generate` anyway, plus a CI job that regenerates and
diffs, plus generated Go that rots; the Bazel rule is one rule and a module
line, builds on both CI architectures, and the object cannot be stale. The
price is the LLVM download (about 1 GB, once per cache: the first CI run of a
change that touches `MODULE.bazel` or the BPF files pays it; the repository
cache covers the rest).

Reproducibility: `-fdebug-compilation-dir=.` and `-ffile-prefix-map` keep the
execroot path out of the object's debug info.

### Testing it

- `bazel test //...` runs the user-space tests: the collector against a fake
  store, `TestObject` (the object's programs, maps and licence) and
  `TestKernelBTF` (the running kernel's BTF has every field the program reads;
  skipped without `/sys/kernel/btf/vmlinux`).
- `TestLoad` loads and attaches the program for real and needs root, so it
  skips under `bazel test`. Run it with sudo on a dev box (any kernel with BTF;
  the verifier is the point):

  ```bash
  bazel build --@rules_go//go/config:pure //cgroup-signals/internal/runqlat:runqlat_test
  sudo bazel-bin/cgroup-signals/internal/runqlat/runqlat_test_/runqlat_test -test.v -test.run Load
  ```

  and the whole thing, `sudo bazel-bin/cgroup-signals/cgroup-signals_/cgroup-signals --runqueue --listen=127.0.0.1:9103`,
  then `curl 127.0.0.1:9103/metrics`. To measure the program's own cost:
  `sudo sysctl kernel.bpf_stats_enabled=1; sudo bpftool prog show` (`run_time_ns`
  and `run_cnt` per program).

The image runs as uid 0 (`user = "0"` in `cgroup-signals/BUILD.bazel`); the
pod needs `CAP_BPF` and `CAP_PERFMON` for `--runqueue` and read access to
`/sys/fs/cgroup`.

## Images and versions

- The registry is named in one build file, `bazel/registry.bzl`
  (`ghcr.io/bpalermo/cgroup-signals`). Do not spell it out elsewhere except the
  README.
- Images are built with the `go_image` macro (`bazel/image/defs.bzl`): layer,
  manifest, an index for `linux/amd64` and `linux/arm64`, load and push. The
  base is `@distroless_static`, pinned by digest in `MODULE.bazel`.
- The version a binary reports comes from `bazel/workspace_status.sh`: `VERSION`
  is the release being worked towards, and a commit tagged `v<VERSION>` is that
  release; any other commit is a snapshot.
- The Helm chart is `chart/cgroup-signals` (rules_helm, helm pinned in
  `MODULE.bazel` and `.bazelrc`). `Chart.yaml` and `values.yaml` carry stamp
  placeholders (`{STABLE_CHART_VERSION}`, `{@//cgroup-signals:image_push.digest}`)
  replaced at package time, so the chart pins the image of its own commit by
  digest. `hardening_test.go` checks the rendered DaemonSets (the defaults, the
  options, and the run-queue one that `runqueue.enabled` adds: BPF and PERFMON
  only, never privileged, cgroupfs read-only), `render_guards_test.sh` that the `fail` guards refuse, and
  `helm_lint_test`/`helm_template_test` lint and render it. The publish job runs
  `bazel/verify-chart.sh` before `...push_registry`; keep the chart's pushed
  version and the README in step with `bazel/workspace_status.sh`. Do not add a
  probe on `/metrics` (a GET resets every memory peak).
- There are TWO images and TWO charts, each chart pinning its image by digest:
  `//cgroup-signals:image_push` (`ghcr.io/bpalermo/cgroup-signals`) with
  `chart/cgroup-signals`, and `//bpftrace:image_push`
  (`ghcr.io/bpalermo/cgroup-signals-bpftrace`) with `chart/bpftrace-debug`.
  `bazel/verify-chart.sh <chart-name> <chart.tgz> <digest> <version> <commit>`
  checks either. The publish job pushes both images, then verifies and pushes
  both charts; keep it, the `lint` job's "publish targets exist" query and
  this list in step when adding a third.
- `//bpftrace` is a debug image (distroless static `:debug` base, pinned by
  digest as `@distroless_static_debug`) holding bpftrace v0.27.1 and bpftool
  v7.8.1, both pinned with sha256 in `MODULE.bazel`. bpftrace's release asset
  is a Nix AppImage, not a static binary: `//appimage-closure` (a Go tool, built
  by Bazel and run in a genrule) reads the squashfs and writes the layer of the
  program and the libraries its `RUNPATH`s lead to, at `/nix/store`. A bpftrace
  bump is the two `http_file` pins; if the AppImage's layout changes the tool
  fails the build (no `entrypoint`, a library in no run path) rather than
  shipping a broken image. `chart/bpftrace-debug` renders ONE privileged
  hostPID Pod bound to `node` (required) with a deadline: it is deliberately
  not a DaemonSet and not a hardened pod; `hardening_test.go` pins what is
  and is not open. The README's one-liners were checked with
  `bpftrace --dry-run`; re-check them on a bpftrace bump.
- Only CI publishes (`.github/workflows/publish.yml`, on `main`). Never push an
  image or create a release by hand.

## CI

`.github/workflows/ci.yml`: `lint` (formatter, Gazelle staleness, the publish
targets exist) always runs; `diff` computes the impacted targets with
bazel-diff (`bazel/ci-impacted-targets.sh`, tested by
`//bazel:ci_impacted_targets_test`); `build` builds and tests only those. Any
doubt (no base, an error) is a full run. Files that change CI outside the
graph (`.bazelrc`, the lint `.bzl` files, `.shellcheckrc`, ...) are the script's
seed list: add any new such file there. `ci` is the single aggregate check.

Third-party actions are pinned to commit SHAs; Dependabot keeps them current.

## Pull requests

- Commits carry `Signed-off-by` (`git commit -s`); no AI attribution.
- Squash merges onto `main`; CI's `diff` uses `HEAD^1` as the base.
