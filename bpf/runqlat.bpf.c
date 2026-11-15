// SPDX-License-Identifier: GPL-2.0-only
//
// Run-queue latency per cgroup: the time from a task becoming runnable (woken,
// or preempted while still runnable) to it getting on a CPU, as a log2
// histogram per tracked cgroup.
//
// The kernel structures are read by direct dereference: in a tp_btf program
// the verifier knows the arguments' BTF types and turns each load into a
// faulting-safe one, which costs far less than a bpf_probe_read_kernel per
// field; CO-RE relocates the offsets through vmlinux.h's
// preserve_access_index.
//
// Adapted from libbpf-tools' runqlat.bpf.c (iovisor/bcc),
// Copyright (c) 2020 Wenbo Zhang, GPL-2.0. The program is GPL-2.0-only and
// loads with the license string "GPL"; the rest of the repository is
// Apache-2.0 (see bpf/README.md).
//
// What differs from runqlat: the histogram is keyed by an index the loader
// assigns to each tracked cgroup (pods and node services), not by a pid or a
// pid namespace; a task's cgroup is resolved through its ancestors, and what
// is under no tracked cgroup counts in index 0 ("other"); the histogram is
// per CPU, so the hot path takes no atomic; and it records the sum of the
// delays, for a Prometheus histogram's _sum. The per-event cost is kept low by
// keeping what is per task in task local storage (the enqueue time and the
// resolved histogram index) instead of hash maps, and by resolving the cgroup
// only at the switch that records a delay.
#include "vmlinux.h"

#include <bpf_core_read.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "runqlat.h"

/* Never reached under a tracked cgroup deeper than this: a pod's container is
 * three levels below kubepods/<qos>, so ancestors are looked up this far. */
#define MAX_DEPTH 8

#define TASK_RUNNING 0

/* Per task: when it became runnable, and the histogram index it counted in
 * last time, with the cgroup and the generation that index was resolved for.
 * Task local storage: no hash lookup on the hot path, and the kernel frees the
 * entry with the task, so there is no table to fill up or to clean. A task is
 * runnable from its wakeup (or preemption) to the switch that puts it on a
 * CPU, which always comes: a task cannot exit without running. */
struct task_info {
	__u64 ts;   /* ktime when it became runnable; 0: not waiting */
	__u64 cgid; /* the cgroup idx was resolved for; 0: never */
	__u32 idx;
	__u32 gen;  /* the value of gen when idx was resolved */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_info);
} tasks SEC(".maps");

/* The generation of the tracked map: the loader adds one after every change to
 * it (a cgroup tracked or dropped), so a resolution remembered in tasks is
 * used only while nothing it depended on can have changed. The program reads
 * it BEFORE it resolves, so a change racing a resolution makes the remembered
 * result stale, never wrong. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} gen SEC(".maps");

/* cgroup id -> histogram index, filled by the loader with the tracked
 * cgroups. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CGROUPS);
	__type(key, __u64);
	__type(value, __u32);
} tracked SEC(".maps");

/* The cgroups below a tracked one, resolved by walking up once and remembered
 * here, so a container costs one lookup after its first switch. Only hits are
 * remembered: a cgroup the loader has not seen yet must resolve again as soon
 * as it has. Least-recently-used, so it needs no cleaning. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u32);
} below SEC(".maps");

/* The histograms, per CPU. The loader reads and sums them at each scrape. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_CGROUPS);
	__type(key, __u32);
	__type(value, struct hist);
} hists SEC(".maps");

/* Counts switches that found no start time: tasks that were runnable before
 * the program attached. Informational. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} missed SEC(".maps");

/* The pre-5.14 name of task_struct.__state, for CO-RE to pick between. */
struct task_struct___old {
	long state;
} __attribute__((preserve_access_index));

/* kernfs_node.parent is __parent since Linux 6.15 (it is read through
 * kernfs_parent(), under RCU). */
struct kernfs_node___new {
	struct kernfs_node___new *__parent;
} __attribute__((preserve_access_index));

static __always_inline struct kernfs_node *kn_parent(struct kernfs_node *kn)
{
	struct kernfs_node___new *n = (void *)kn;

	if (bpf_core_field_exists(n->__parent))
		return (struct kernfs_node *)n->__parent;
	return kn->parent;
}

static __always_inline long task_state(struct task_struct *t)
{
	struct task_struct___old *old = (void *)t;

	if (bpf_core_field_exists(old->state))
		return old->state;
	return t->__state;
}

static __always_inline void enqueue(struct task_struct *t, __u64 now)
{
	struct task_info *ti;

	ti = bpf_task_storage_get(&tasks, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ti)
		ti->ts = now;
}

static __always_inline __u32 lookup(__u64 id)
{
	__u32 *idx = bpf_map_lookup_elem(&tracked, &id);

	return idx ? *idx : 0;
}

/* The histogram index of the cgroup kn: of the cgroup itself if it
 * is tracked, else of its nearest tracked ancestor, else 0. */
static __always_inline __u32 resolve(struct kernfs_node *kn)
{
	__u64 leaf, id;
	__u32 *idx, found;
	int i;

	if (!kn)
		return 0;
	leaf = kn->id;
	idx = bpf_map_lookup_elem(&below, &leaf);
	if (idx)
		return *idx;
	found = lookup(leaf);
	if (found)
		return found;
	for (i = 0; i < MAX_DEPTH; i++) {
		kn = kn_parent(kn);
		if (!kn)
			return 0;
		id = kn->id;
		found = lookup(id);
		if (found) {
			bpf_map_update_elem(&below, &leaf, &found, BPF_ANY);
			return found;
		}
	}
	return 0;
}

static __always_inline __u32 log2l(__u64 v)
{
	__u32 r = 0;

	/* The BPF verifier needs the loop bounded; 6 steps cover 64 bits. */
	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

/* ns / 1000. BPF has no 64-bit multiply-high, so clang leaves a 64-bit
 * division by a constant as a real division; for a 32-bit value the exact
 * reciprocal multiplication is three instructions (x * 274877907 >> 38 is
 * exact for every x below 2^32). Only delays of 4.3 s or more take the
 * division. */
static __always_inline __u64 ns_to_us(__u64 ns)
{
	if (ns >> 32)
		return ns / 1000;
	return (ns * 274877907ULL) >> 38;
}

static __always_inline void record(__u32 idx, __u64 delta_ns)
{
	__u32 slot = log2l(ns_to_us(delta_ns));
	struct hist *h;

	if (idx >= MAX_CGROUPS)
		idx = 0;
	h = bpf_map_lookup_elem(&hists, &idx);
	if (!h)
		return;
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	/* Per CPU, and the program runs with migration disabled: no atomic. */
	h->slots[slot]++;
	h->sum_ns += delta_ns;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	enqueue(p, bpf_ktime_get_ns());
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	enqueue(p, bpf_ktime_get_ns());
	return 0;
}

static __noinline void missed_one(void)
{
	__u32 zero = 0;
	__u64 *m = bpf_map_lookup_elem(&missed, &zero);

	if (m)
		(*m)++;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u64 now = bpf_ktime_get_ns();
	struct task_info *ti;
	__u32 zero = 0, *g, gv, idx;
	struct kernfs_node *kn;
	__s64 delta;
	__u64 cgid;

	/* Back on the run queue: preempted (the scheduler leaves a preempted
	 * task runnable whatever its state says, which can already be a sleep
	 * state it was about to enter), or it yielded and is still runnable.
	 * The idle task (pid 0) is not timed; it also shows as preempted. */
	if (prev->pid && (preempt || task_state(prev) == TASK_RUNNING))
		enqueue(prev, now);

	if (!next->pid)
		return 0;
	ti = bpf_task_storage_get(&tasks, next, 0, 0);
	if (!ti || !ti->ts) {
		missed_one();
		return 0;
	}
	delta = now - ti->ts;
	ti->ts = 0;
	if (delta < 0)
		return 0;

	/* The histogram index: remembered per task while the task is in the
	 * same cgroup and the tracked set has not changed since. */
	g = bpf_map_lookup_elem(&gen, &zero);
	if (!g)
		return 0;
	gv = *g; /* before resolving, once */
	kn = next->cgroups->dfl_cgrp->kn;
	cgid = kn ? kn->id : 0;
	if (cgid && ti->cgid == cgid && ti->gen == gv) {
		idx = ti->idx;
	} else {
		idx = resolve(kn);
		ti->cgid = cgid;
		ti->idx = idx;
		ti->gen = gv;
	}
	record(idx, delta);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
