/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * A hand-trimmed vmlinux.h: the BPF UAPI constants and the four kernel
 * structures runqlat.bpf.c reads, nothing else.
 *
 * Why trimmed: bpftool's full dump (`bpftool btf dump file /sys/kernel/btf/vmlinux
 * format c`) is some 100k lines and 3 MB, differs per kernel config, and CO-RE
 * does not need it: a field is relocated by the NAME of its struct and field
 * against the BTF of the kernel that loads the program, so only the fields
 * read have to be declared, in any layout. Each struct below is therefore a
 * subset of the kernel's, with preserve_access_index so that every access is
 * relocated. Offsets and sizes here are NOT the kernel's and must never be
 * used as such.
 *
 * Fields, as of Linux 6.8 and 6.18 (checked with
 * `bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A.. "STRUCT 'task_struct'"`):
 *   task_struct.__state (int; `state`, a long, before 5.14), .pid, .cgroups
 *   css_set.dfl_cgrp, cgroup.kn, kernfs_node.id (u64 since 5.5), and
 *   kernfs_node.parent, which is __parent from 6.15 (the program has both)
 * The load test (TestLoad, needs root) fails if the running kernel lacks one.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef signed char __s8;
typedef short int __s16;
typedef int __s32;
typedef long long int __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef __u16 __sum16;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef int pid_t;
typedef long unsigned int size_t;
typedef _Bool bool;

enum {
	false = 0,
	true = 1,
};

/* include/uapi/linux/bpf.h */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

enum {
	BPF_F_NO_PREALLOC = 1,
};

enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

struct kernfs_node {
	struct kernfs_node *parent;
	__u64 id;
};

struct cgroup {
	struct kernfs_node *kn;
};

struct css_set {
	struct cgroup *dfl_cgrp;
};

struct task_struct {
	int __state;
	pid_t pid;
	struct css_set *cgroups;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
