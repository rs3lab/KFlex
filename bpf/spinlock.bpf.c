// SPDX-License-Identifier: GPL-2.0
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

uint64_t ekcache_allocmap_base_ptr;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_MMAPABLE);
} allocmap SEC(".maps");

struct ekc_lock_node {
  struct ekc_lock_node *next;
  bool locked;
};

struct ekc_spin_lock {
  struct ekc_lock_node *tail;
};

static __always_inline void ekc_spin_lock(void *region, struct ekc_spin_lock *lock, struct ekc_lock_node *node) {
  struct ekc_lock_node *pred;
  u64 offset;

  pred = __sync_lock_test_and_set(&lock->tail, node);
  if (pred) {
    node->locked = true;
    offset = bpf_unknown_cast(pred) - bpf_unknown_cast(region);
    bpf_assert_range_with(offset, 0, sizeof(struct ekc_lock_node) * 2047, TC_ACT_SHOT + 1);
    pred = region + offset;
    WRITE_ONCE(pred->next, node);
    loop {
      if (!READ_ONCE(node->locked)) {
        break;
      }
    }
  }
}

static __always_inline void ekc_spin_unlock(void *region, struct ekc_spin_lock *lock, struct ekc_lock_node *node) {
  struct ekc_lock_node *next = READ_ONCE(node->next);
  u64 offset;
  int i = -1;

  if (!next) {
    if (__sync_val_compare_and_swap(&lock->tail, node, NULL) == node) {
      return;
    }
  }
  loop {
    next = READ_ONCE(node->next);
    if (next) {
      break;
    }
  }
  offset = (u64)next - bpf_unknown_cast(region);
  bpf_assert_range_with(offset, 0, sizeof(struct ekc_lock_node) * 2047, TC_ACT_SHOT + 1);
  next = region + offset;
  WRITE_ONCE(next->locked, false);
  WRITE_ONCE(node->next, NULL);
}

struct ekc_spin_lock lock;
struct ekc_lock_node nodes[2048];
int counter;

static __always_inline void *ekc_kptr_to_uptr(void *ptr) {
  u64 offset = bpf_unknown_cast(ptr) - bpf_unknown_cast(nodes);
  return (void *)ekcache_allocmap_base_ptr + offset;
}

static __always_inline void *ekc_uptr_to_kptr(void *ptr) {
  u64 offset = bpf_unknown_cast(ptr) - ekcache_allocmap_base_ptr;
  bpf_assert_range_with(offset, 0, sizeof(nodes) - sizeof(nodes[0]), TC_ACT_SHOT + 1);
  return (void *)nodes + offset;
}

static __always_inline void ekc_shared_spin_lock(struct ekc_spin_lock *lock, struct ekc_lock_node *node) {
  struct ekc_lock_node *pred, *unode;
  u64 offset;

  unode = ekc_kptr_to_uptr(node);
  pred = __sync_lock_test_and_set(&lock->tail, unode);
  if (pred) {
    node->locked = true;
    pred = ekc_uptr_to_kptr(pred);
    WRITE_ONCE(pred->next, ekc_kptr_to_uptr(node));
    loop {
      if (!READ_ONCE(node->locked)) {
        break;
      }
    }
  }
}

static __always_inline void ekc_shared_spin_unlock(struct ekc_spin_lock *lock, struct ekc_lock_node *node) {
  struct ekc_lock_node *next = READ_ONCE(node->next);
  u64 offset;
  int i = -1;

  if (!next) {
    struct ekc_lock_node *unode = ekc_kptr_to_uptr(node);
    if (__sync_val_compare_and_swap(&lock->tail, unode, NULL) == unode) {
      return;
    }
    loop {
      next = READ_ONCE(node->next);
      if (next) {
        break;
      }
    }
  }
  next = ekc_uptr_to_kptr(next);
  WRITE_ONCE(next->locked, false);
  WRITE_ONCE(node->next, NULL);
}

SEC("tc")
int ekcache_spinlock(struct __sk_buff *ctx) {
  int cpu = bpf_get_smp_processor_id();
  ekc_spin_lock(nodes, &lock, nodes + cpu);
  bpf_printk("[%d] old=%d new=%d", cpu, counter, counter + 1);
  counter++;
  int i;
  bpf_for(i, 0, 200000);
  ekc_spin_unlock(nodes, &lock, nodes + cpu);
  return TC_ACT_OK;
}

SEC("tc")
int ekcache_shared_spinlock(struct __sk_buff *ctx) {
  int cpu = bpf_get_smp_processor_id();
  ekc_shared_spin_lock(&lock, nodes + cpu);
  bpf_printk("[%d] old=%d new=%d", cpu, counter, counter + 1);
  counter++;
  int i;
  bpf_for(i, 0, 200000);
  ekc_shared_spin_unlock(&lock, nodes + cpu);
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
