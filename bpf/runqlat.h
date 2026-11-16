/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Shared by runqlat.bpf.c and, by copy of the numbers, the Go loader
 * (cgroup-signals/internal/runqlat): keep MAX_SLOTS and the layout of struct
 * hist equal on both sides. */
#ifndef CGROUP_SIGNALS_RUNQLAT_H
#define CGROUP_SIGNALS_RUNQLAT_H

/* Slot k holds the delays of (2^k, 2^(k+1)] units of 2^-20 s (about 0.954 us;
 * slot 0: up to 2 units), the last slot everything over 2^(MAX_SLOTS-1) units
 * (2048 s): slot k is bucket k-19 of a native histogram of schema 0, upper
 * bound included as there. */
#define MAX_SLOTS 32

/* Tracked cgroups, "other" included: the size of the histogram array. The
 * loader sets the real cap through the map's max_entries; this is the most it
 * can set. */
#define MAX_CGROUPS 4096

struct hist {
	__u64 slots[MAX_SLOTS];
	__u64 sum_ns;
};

#endif /* CGROUP_SIGNALS_RUNQLAT_H */
