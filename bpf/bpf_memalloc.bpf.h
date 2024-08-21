// SPDX-License-Identifier: GPL-2.0
#ifndef EKCACHE_BPF_BPF_MEMALLOC_BPF_H
#define EKCACHE_BPF_BPF_MEMALLOC_BPF_H

// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <ekc_list.bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARENA);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_MMAPABLE);
} arena SEC(".maps");

//uint64_t __arena_map_base;

SEC("tc")
int __arena_map_get_base(struct __sk_buff *ctx) {
  struct bpf_arena *map = (void *)&arena;
  //__arena_map_base = (u64)map->value;
  return 0;
}

struct ekc_slist_head *head[1024];

static __always_inline void *get_cpu_head(int cpu) {
  return bpf_uptr_force_cast(head[cpu], &arena, bpf_core_type_id_local(typeof(*head[0])));
}

static __always_inline void *bpf_malloc(u32 type_id) {
  int cpu = bpf_get_smp_processor_id();
  struct ekc_slist_head *elem, *next;

  bpf_preempt_disable();
  // Get a uptr when giving in a useraddr
  elem = get_cpu_head(cpu);
  if (!elem) {
    bpf_preempt_enable();
    return NULL;
  }
  next = elem->next;
  // Translate back to useraddr
  head[cpu] = next;
  bpf_preempt_enable();
  return bpf_uptr_cast((void *)elem + sizeof(*elem), type_id);
}

static __always_inline void bpf_free(void *ptr) {
  int cpu = bpf_get_smp_processor_id();
  struct ekc_slist_head *elem, *next;

  bpf_preempt_disable();
  // Get a new uptr of the header of allocation
  elem = bpf_uptr_cast(ptr - sizeof(*elem), bpf_core_type_id_local(typeof(*head[0])));
  elem->next = head[cpu];
  head[cpu] = elem;
  bpf_preempt_enable();
}

#define emalloc(type) bpf_malloc(bpf_core_type_id_local(type))
#define efree(ptr) bpf_free(ptr)

#endif
