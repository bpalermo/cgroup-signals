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
// keeping what is per thread in an array by tid (the enqueue time and the
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

/* Per thread, by tid: when it became runnable, and the histogram index it
 * counted in last time, with the cgroup and the generation that index was
 * resolved for. A plain array: the lookup is inlined by the verifier (no
 * helper call, no hashing, no pointer chase through the task's local storage,
 * which on a small core is several cache misses), and one entry is one cache
 * line. The loader sizes it to the kernel's pid_max; a tid beyond it is not
 * timed (counted in missed). Nothing is cleaned: a thread is runnable from its
 * wakeup (or preemption) to the switch that puts it on a CPU, which always
 * comes, and what is remembered about the cgroup is a function of the cgroup
 * and the generation alone, so a tid reused by another task is harmless. */
struct task_info {
	__u64 ts;   /* ktime when it became runnable; 0: not waiting */
	__u64 cgid; /* the cgroup idx was resolved for; 0: never */
	__u32 idx;
	__u32 gen;  /* the value of tracked_gen when idx was resolved */
	__u64 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 32768);
	__type(key, __u32);
	__type(value, struct task_info);
} tids SEC(".maps");

/* The tids the array does not reach (the loader caps it below a huge pid_max):
 * the same record in an LRU hash, slower and rarely used, so that coverage
 * does not depend on how high the kernel's PID allocator has climbed. The
 * LRU evicts the entries of threads that are gone. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct task_info);
} tids_hi SEC(".maps");

/* The generation of the tracked map: the loader adds one after every change to
 * it (a cgroup tracked or dropped), so a resolution remembered above is used
 * only while nothing it depended on can have changed. The program reads it
 * BEFORE it resolves, so a change racing a resolution makes the remembered
 * result stale, never wrong. A global (the .bss map value, read with two
 * instructions), written by the loader. */
volatile __u32 tracked_gen;

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
 * as it has. An entry is used only under the generation it was made in, so a
 * dropped cgroup's index, or one given to another cgroup, is never served from
 * here. Least-recently-used, so it needs no cleaning. */
struct below_val {
	__u32 idx;
	__u32 gen;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct below_val);
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

/* A tid beyond the array. */
static __noinline void enqueue_hi(__u32 tid, __u64 now)
{
	struct task_info *ti = bpf_map_lookup_elem(&tids_hi, &tid);
	struct task_info n = {};

	if (ti) {
		ti->ts = now;
		return;
	}
	n.ts = now;
	bpf_map_update_elem(&tids_hi, &tid, &n, BPF_ANY);
}

static __always_inline void enqueue(struct task_struct *t, __u64 now)
{
	__u32 tid = t->pid;
	struct task_info *ti = bpf_map_lookup_elem(&tids, &tid);

	if (ti) {
		ti->ts = now;
		return;
	}
	enqueue_hi(tid, now);
}

static __always_inline __u32 lookup(__u64 id)
{
	__u32 *idx = bpf_map_lookup_elem(&tracked, &id);

	return idx ? *idx : 0;
}

/* The histogram index of the cgroup kn: of the cgroup itself if it
 * is tracked, else of its nearest tracked ancestor, else 0. */
static __always_inline __u32 resolve(struct kernfs_node *kn, __u32 gv)
{
	__u64 leaf, id;
	struct below_val *bv, nv;
	__u32 found;
	int i;

	if (!kn)
		return 0;
	leaf = kn->id;
	bv = bpf_map_lookup_elem(&below, &leaf);
	if (bv && bv->gen == gv)
		return bv->idx;
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
			nv.idx = found;
			nv.gen = gv;
			bpf_map_update_elem(&below, &leaf, &nv, BPF_ANY);
			return found;
		}
	}
	return 0;
}

/* floor(log2(v)) of a 32-bit value (0 for 0): five compare-and-shifts,
 * on 32-bit registers (a 64-bit one costs the compiler twice the code). */
static __always_inline __u32 log2u32(__u32 v)
{
	__u32 r = 0;

	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

/* The slot of a delay: slot k holds delays of [2^k, 2^(k+1)) units of 2^-20 s
 * (about 0.954 us), slot 0 everything under 2 units, the last slot everything
 * from 2^(MAX_SLOTS-1) units (8 s) up. The unit makes slot k exactly bucket
 * k-19 of a Prometheus native histogram of schema 0 (powers of two seconds).
 *
 * A unit is 1e9/2^20 = 1953125/2048 ns, so the first delay of slot k is
 * ceil(1953125 * 2^k / 2048) ns. For ns in [2^j, 2^(j+1)) the slot is j-10 or
 * j-9 (1953125/2048 is 2^9.897), so one floor(log2) and one compare give it,
 * with no division. Mirrored by slotOf in cgroup-signals/internal/runqlat. */
#define SLOT1_NS 1908 /* ceil(1953125 * 2 / 2048): the first delay of slot 1 */

static __always_inline __u32 slot_of(__u64 ns)
{
	__u32 j, k;

	if (ns < SLOT1_NS)
		return 0;
	j = (ns >> 32) ? 32 + log2u32((__u32)(ns >> 32)) : log2u32((__u32)ns);
	k = j - 10; /* ns >= 1908 > 2^10, so j >= 10 */
	if (k >= MAX_SLOTS - 1)
		return MAX_SLOTS - 1;
	if (ns >= ((1953125ULL << (k + 1)) + 2047) >> 11)
		k++;
	return k;
}

static __always_inline void record(__u32 idx, __u64 delta_ns)
{
	__u32 slot = slot_of(delta_ns);
	struct hist *h;

	h = bpf_map_lookup_elem(&hists, &idx);
	if (!h)
		return;
	if (slot >= MAX_SLOTS) /* never, but the verifier cannot know */
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
	__u32 tid = next->pid, gv, idx;
	struct kernfs_node *kn;
	__s64 delta;
	__u64 cgid;

	/* Back on the run queue: preempted (the scheduler leaves a preempted
	 * task runnable whatever its state says, which can already be a sleep
	 * state it was about to enter), or it yielded and is still runnable.
	 * The idle task (pid 0) is not timed; it also shows as preempted. */
	if (prev->pid && (preempt || task_state(prev) == TASK_RUNNING))
		enqueue(prev, now);

	if (!tid)
		return 0;
	ti = bpf_map_lookup_elem(&tids, &tid);
	if (!ti)
		ti = bpf_map_lookup_elem(&tids_hi, &tid);
	if (!ti || !ti->ts) {
		missed_one();
		return 0;
	}
	delta = now - ti->ts;
	ti->ts = 0;
	if (delta < 0)
		return 0;

	/* The histogram index: remembered per thread while the task is in the
	 * same cgroup and the tracked set has not changed since. */
	gv = tracked_gen; /* before resolving, once */
	kn = next->cgroups->dfl_cgrp->kn;
	cgid = kn ? kn->id : 0;
	if (cgid && ti->cgid == cgid && ti->gen == gv) {
		idx = ti->idx;
	} else {
		idx = resolve(kn, gv);
		ti->cgid = cgid;
		ti->idx = idx;
		ti->gen = gv;
	}
	record(idx, delta);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
