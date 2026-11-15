# bpf

The CO-RE eBPF programs. See "BPF" in [AGENTS.md](../AGENTS.md) for how they are
built, loaded and tested.

| File | |
| --- | --- |
| `runqlat.bpf.c` | run-queue latency per cgroup: `tp_btf` on `sched_wakeup`, `sched_wakeup_new`, `sched_switch` |
| `runqlat.h` | `MAX_SLOTS`, `MAX_CGROUPS` and `struct hist`, shared with the Go loader |
| `vmlinux.h` | the kernel structures the programs read, trimmed by hand (its header says why) |

## Licence

`runqlat.bpf.c` is adapted from `libbpf-tools/runqlat.bpf.c` of
[iovisor/bcc](https://github.com/iovisor/bcc) (Copyright (c) 2020 Wenbo Zhang,
GPL-2.0) and is **GPL-2.0-only**, as its SPDX line says; the object it compiles
to declares the licence `GPL`, which the kernel requires of a program that calls
GPL-only helpers. `runqlat.h` is `LGPL-2.1 OR BSD-2-Clause` like the header it
descends from, and `vmlinux.h` is GPL-2.0-only (it mirrors kernel declarations).
The compiled object is embedded in the Go binary as data and loaded into the
kernel; the Go code around it is Apache-2.0 (see [LICENSE](../LICENSE)) and is
neither linked with nor derived from the BPF program.
