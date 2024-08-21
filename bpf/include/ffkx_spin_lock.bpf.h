// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_SPIN_LOCK_BPF_H
#define FFKX_BPF_FFKX_SPIN_LOCK_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_helpers.h>
#include <ffkx_atomic.bpf.h>
#include <ffkx_helpers.bpf.h>

struct ffkx_lock_node {
  struct ffkx_lock_node *next;
  bool locked;
};

struct ffkx_spin_lock {
  struct ffkx_lock_node *tail;
};

extern struct ffkx_lock_node ffkx_cpu_lock_nodes[1] SEC(".data.ffkx_per_cpu_lock_nodes");

// We mark this function as hidden so that it is marked with static linkage in
// the BTF of the program, so that it is not treated as a global function.
__hidden void ffkx_spin_lock_slowpath(struct ffkx_lock_node *pred, struct ffkx_lock_node *node);

static __always_inline struct ffkx_lock_node *ffkx_get_cpu_node(void) {
  int cpu = bpf_get_smp_processor_id();
  return &ffkx_cpu_lock_nodes[cpu];
}

static __always_inline void __ffkx_spin_lock(struct ffkx_spin_lock *lock, bool preempt) {
  struct ffkx_lock_node *pred, *node;

  ffkx_preempt_disable();
  node = ffkx_get_cpu_node();
  pred = ffkx_atomic_xchg(&lock->tail, node);
  if (pred) {
    ffkx_spin_lock_slowpath(pred, node);
  }
  if (!preempt) {
    ffkx_preempt_enable();
  }
}

static __always_inline void __ffkx_spin_unlock(struct ffkx_spin_lock *lock, bool preempt) {
  struct ffkx_lock_node *next, *node;

  if (!preempt) {
    ffkx_preempt_disable();
  }
  next = FFKX_READ_ONCE(lock->tail);
  node = ffkx_get_cpu_node();
  if (!next) {
    if (ffkx_atomic_cmpxchg(&lock->tail, node, NULL) == node) {
      return;
    }
  }
  // TODO(kkd): Replace bpf_repeat with lightweight loop iterator
  bpf_repeat(BPF_MAX_LOOPS) {
    next = FFKX_READ_ONCE(node->next);
    if (next) {
      break;
    }
  }
  ffkx_smp_store_release(&next->locked, false);
  FFKX_WRITE_ONCE(node->next, NULL);
  ffkx_preempt_enable();
}

static __always_inline void ffkx_spin_lock(struct ffkx_spin_lock *lock) { __ffkx_spin_lock(lock, true); }

static __always_inline void ffkx_spin_lock_nopreempt(struct ffkx_spin_lock *lock) { __ffkx_spin_lock(lock, false); }

#endif
