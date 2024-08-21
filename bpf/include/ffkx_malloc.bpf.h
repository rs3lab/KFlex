// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_MALLOC_BPF_H
#define FFKX_BPF_FFKX_MALLOC_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.h>
#include <ffkx_atomic.bpf.h>
#include <ffkx_heap.bpf.h>
#include <ffkx_log.bpf.h>
#include <ffkx_malloc.h>
#include <ffkx_util.bpf.h>

void bpf_preempt_disable(void) __ksym;
void bpf_preempt_enable(void) __ksym;

struct ffkx_malloc_lock {
  struct bpf_spin_lock lock;
};

// Used to obtain the base address of heap for use in user space.
uint64_t ffkx_malloc_heap_kbase;
// Used to obtain the mask for usage in memcpy/memcmp functions.
uint64_t ffkx_malloc_heap_kmask;
// TODO(kkd): Find a better way using a mathematical computation.
// The map to translate all sizes to index without computation.
unsigned int ffkx_malloc_size_map[FFKX_MALLOC_SIZE_MAP_SZ];
// The malloc caches.
struct ffkx_malloc_caches ffkx_malloc_caches;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct ffkx_malloc_lock);
  __uint(max_entries, FFKX_MALLOC_SIZE_CLASS);
} ffkx_malloc_lock_map SEC(".maps");

static inline int ffkx_malloc_size_to_index(unsigned int size) { return ffkx_malloc_size_map[size]; }

static inline bool ffkx_malloc_pcpu_cache_avail(void) { return !!ffkx_malloc_caches.pcpu; }

static inline bool ffkx_malloc_global_cache_avail(void) { return !!ffkx_malloc_caches.global; }

static inline struct ffkx_malloc_size_cache *ffkx_malloc_get_pcpu_cache(unsigned int idx) {
  auto pcpu = &ffkx_malloc_caches.pcpu[bpf_get_smp_processor_id()].sizes[idx];
  cast(typeof(*pcpu), pcpu);
  return pcpu;
}

static inline struct ffkx_malloc_size_cache *ffkx_malloc_get_global_cache(unsigned int idx) {
  auto global = &ffkx_malloc_caches.global->sizes[idx];
  cast(typeof(*global), global);
  return global;
}

static inline struct ffkx_malloc_lock *ffkx_malloc_get_lock(unsigned int idx) {
  return bpf_map_lookup_elem(&ffkx_malloc_lock_map, &idx);
}

// Requires that global cache is available
static __noinline void ffkx_malloc_refill_pcpu(unsigned int idx, const int batch) {
  // TODO(kkd): Throw
  auto lock = ffkx_malloc_get_lock(idx);
  if (!lock) {
    return;
  }
  auto global = ffkx_malloc_get_global_cache(idx);
  bpf_spin_lock(&lock->lock);
  // If global reserves are running low, we shouldn't consume all items for
  // ourselves, instead let's keep contending for the last few for better
  // sharing among CPUs.
  if (global->count < batch) {
    bpf_spin_unlock(&lock->lock);
    return;
  }
  auto head = global->head;
  auto last = head;
  auto tail = head->next;
  if (tail) {
    for (int i = 1; i < batch; i++) {
      last = tail;
      tail = tail->next;
    }
  }
  global->head = tail;
  if (!tail) {
    global->tail = NULL;
  }
  global->count -= batch;
  bpf_spin_unlock(&lock->lock);
  // [head, last] can be added to pcpu list
  // Note that migration is disabled in BPF progs, so we're on the same CPU
  bpf_preempt_disable();
  auto pcpu = ffkx_malloc_get_pcpu_cache(idx);
  last->next = pcpu->head;
  pcpu->head = head;
  if (!last->next) {
    pcpu->tail = last;
  }
  pcpu->count += batch;
  bpf_preempt_enable();
}

// Caches for malloc can start oversized (> high watermark), but then they enter
// the refill feedback loop once they go below low watermark, as we want to
// amortize cost of going to global pool.
static __noinline void *ffkx_malloc(unsigned int size) {
  // Sizes must be within PAGE_SIZE
  if (size > 4096) {
    return NULL;
  }
  auto idx = ffkx_malloc_size_to_index(size);
  if (idx < 0 || idx >= FFKX_MALLOC_SIZE_CLASS) {
    return NULL;
  }
  // per-CPU mode may be disabled, do global allocation.
  if (!ffkx_malloc_pcpu_cache_avail()) {
    goto check_global;
  }
  auto pcpu = ffkx_malloc_get_pcpu_cache(idx);
  // Check count to avoid translation.
  // If we don't have anything, pull some items from global list.
  if (!pcpu->count && ffkx_malloc_global_cache_avail()) {
    ffkx_malloc_refill_pcpu(idx, 2 * FFKX_MALLOC_PCPU_LOW_WATERMARK);
  }
  // Drain per-CPU item
  if (pcpu->count) {
    bpf_preempt_disable();
    auto head = pcpu->head;
    // FIXME: This should not be needed, debug later why removing it fails
    // verification... For Redis
    cast(typeof(*head), head);
    pcpu->head = head->next;
    pcpu->count--;
    if (!pcpu->head) {
      pcpu->tail = NULL;
    }
    bpf_preempt_enable();
    // Let's refill pcpu cache from global reserves, 128 at a time
    if (pcpu->count <= FFKX_MALLOC_PCPU_LOW_WATERMARK && ffkx_malloc_global_cache_avail()) {
      // WARNING: Ensure batch size doesn't end up crossing HIGH_HALF, as we won't set
      // splice_head here.
      _Static_assert((3 * FFKX_MALLOC_PCPU_LOW_WATERMARK) < FFKX_MALLOC_PCPU_HIGH_WATERMARK_HALF, "BUG");
      ffkx_malloc_refill_pcpu(idx, 3 * FFKX_MALLOC_PCPU_LOW_WATERMARK);
    }
    struct ffkx_malloc_object_hdr *hdr = (void *)head;
    type_cast(typeof(*hdr), hdr);
    // Assert
    if (hdr->index != idx) {
      return NULL;
    }
    return hdr + 1;
  }
  // TODO(kkd): Before searching global cache, we could try the next size class
  // as best effort.
check_global:
  if (!ffkx_malloc_global_cache_avail()) {
    return NULL;
  }
  // TODO(kkd): Throw
  auto lock = ffkx_malloc_get_lock(idx);
  if (!lock) {
    return NULL;
  }
  // Drain the global cache
  bpf_spin_lock(&lock->lock);
  auto global = ffkx_malloc_get_global_cache(idx);
  if (global->count) {
    auto head = global->head;
    global->head = head->next;
    global->count--;

    if (!global->head) {
      global->tail = NULL;
    }

    // TODO(kkd): Introduce watermark based wakeup for background thread.
    // Do outside lock.
    if (global->count <= FFKX_MALLOC_GLOBAL_LOW_WATERMARK && 0) {
      // TODO(kkd): Fire userspace logic to refill pool for idx
    }
    bpf_spin_unlock(&lock->lock);
    struct ffkx_malloc_object_hdr *hdr = (void *)head;
    type_cast(typeof(*hdr), hdr);
    // Assert
    if (hdr->index != idx) {
      return NULL;
    }
    return hdr + 1;
  }
  bpf_spin_unlock(&lock->lock);
  return NULL;
}

static __noinline void ffkx_free_global(struct ffkx_slist_head *item, u64 idx);
// Caches can being oversized (> high watermark), they only enter reclaim logic
// once they breach the half way pointer (dip and come back up), which indicates
// stuff is moving from one pcpu cache to another, then it's better to utilize
// the global list for sharing.
static __noinline void ffkx_free(void *ptr) {
  struct ffkx_slist_head *splice_head;
  struct ffkx_slist_head *splice_tail;
  struct ffkx_slist_head *item;

  if (!ptr) {
    return;
  }
  ptr -= sizeof(struct ffkx_malloc_object_hdr);
  // TODO(kkd): BUG: type_cast(void, ptr) crashes
  item = ptr;
  type_cast(struct ffkx_malloc_object_hdr, ptr);
  type_cast(typeof(*item), item);
  auto idx = *(u64 *)(ptr + 8);

  // If no per-CPU cache, we drew the element from the global cache, return back
  // to it.
  if (!ffkx_malloc_pcpu_cache_avail()) {
    return ffkx_free_global(item, idx);
  }
  auto pcpu = ffkx_malloc_get_pcpu_cache(idx);
  bpf_preempt_disable();
  // Whenever we reach the mid-way pointer in our high watermark, remember the
  // item at this position, so we can constant time splice half of the list into
  // the global pool quickly, from item->next to end. We don't need to clear it
  // as we draw elements and empty the pcpu cache, as we only access splice_head
  // on breaching the high watermark, at which point it should be up to date.
  if (pcpu->count == FFKX_MALLOC_PCPU_HIGH_WATERMARK_HALF - 1) {
    pcpu->splice_head = item;
  }
  // Free element
  item->next = pcpu->head;
  pcpu->head = item;
  auto count = ++pcpu->count;
  if (!item->next) {
    pcpu->tail = item;
  }
  // We could do this async, but then pcpu ops will have to be atomic. Let's
  // just amortize the cost instead.
  // TODO(kkd): We should probably splice the latter part of the list, since
  // these elements are more likely to be in-cache than the older ones.
  //
  // Also, we might start with count > watermark, go below and come back at it,
  // in such a case splice_head won't be set (pcpu cache is oversized for some
  // evaluation), so we need to check whether we can splice or not.
  //
  // If global caches are disabled, there can be no memory conservation during
  // imbalance.
  if (count >= FFKX_MALLOC_PCPU_HIGH_WATERMARK && pcpu->splice_head && ffkx_malloc_global_cache_avail()) {
    // Extract latter half of list.
    // splice_head might be badly named (TODO(kkd))...
    // more like splice_point.
    splice_head = pcpu->splice_head->next;
    splice_tail = pcpu->tail;
    // Update length to half.
    pcpu->count = FFKX_MALLOC_PCPU_HIGH_WATERMARK_HALF;
    // New tail is splice_head.
    pcpu->tail = pcpu->splice_head;
    // New splice_head is set as current head.
    // If head is now removed (count going to HALF - 1), not updating
    // splice_head is not problematic, as we only need it when we go back to
    // high watermark, at which point it will be updated on free at  HALF - 1
    // again.
    pcpu->splice_head = pcpu->head;
    bpf_preempt_enable();
    goto fill;
  }
  bpf_preempt_enable();
  return;

fill:;
  // TODO(kkd): Throw, Can't be NULL, but oh well.
  auto lock = ffkx_malloc_get_lock(idx);
  if (!lock) {
    return;
  }
  bpf_spin_lock(&lock->lock);
  // Should be non-NULL, as we checked for avail before arriving
  auto global = ffkx_malloc_get_global_cache(idx);
  // Insert [splice_head, splice_tail]
  splice_tail->next = global->head;
  global->head = splice_head;
  count = (global->count += FFKX_MALLOC_PCPU_HIGH_WATERMARK_HALF);
  if (!splice_tail->next) {
    global->tail = splice_tail;
  }
  // TODO(kkd): We might want to kickstart reclaim in background if we have too
  // many objects. But less urgent as everyone can pull from global lists.
  if (count >= FFKX_MALLOC_GLOBAL_HIGH_WATERMARK && 0) {
    // TODO(kkd):
  }
  bpf_spin_unlock(&lock->lock);
  return;
}

// Free into the global cache
static __noinline void ffkx_free_global(struct ffkx_slist_head *item, u64 idx) {
  // TODO(kkd): Throw, Can't be NULL, but oh well.
  auto lock = ffkx_malloc_get_lock(idx);
  if (!lock) {
    return;
  }
  bpf_spin_lock(&lock->lock);
  // Must be non-NULL
  auto global = ffkx_malloc_get_global_cache(idx);
  item->next = global->head;
  global->head = item;
  if (!item->next) {
    global->tail = item;
  }
  global->count++;
  bpf_spin_unlock(&lock->lock);
}

#endif
