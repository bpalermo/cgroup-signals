/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Shared by runqlat.bpf.c and, by copy of the numbers, the Go loader
 * (cgroup-signals/internal/runqlat): keep MAX_SLOTS and the layout of struct
 * hist equal on both sides. */
#ifndef CGROUP_SIGNALS_RUNQLAT_H
#define CGROUP_SIGNALS_RUNQLAT_H

/* Slot k holds the delays of [2^k, 2^(k+1)) microseconds (slot 0: under 2 us);
 * the last slot is everything from 2^(MAX_SLOTS-1) us (about 8.4 s) up. */
#define MAX_SLOTS 24

/* Tracked cgroups, "other" included: the size of the histogram array. The
 * loader sets the real cap through the map's max_entries; this is the most it
 * can set. */
#define MAX_CGROUPS 4096

struct hist {
	__u64 slots[MAX_SLOTS];
	__u64 sum_ns;
};

#endif /* CGROUP_SIGNALS_RUNQLAT_H */
