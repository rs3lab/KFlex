// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_HASHMAP_BPF_H
#define FFKX_BPF_FFKX_HASHMAP_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.h>
#include <ffkx_atomic.bpf.h>
#include <ffkx_errno.bpf.h>
#include <ffkx_hashmap.h>
#include <ffkx_heap.bpf.h>
#include <ffkx_jhash.bpf.h>
#include <ffkx_log.bpf.h>
#include <ffkx_malloc.bpf.h>
#include <ffkx_util.bpf.h>
#include <list_nulls.bpf.h>
#include <rculist_nulls.bpf.h>

struct ffkx_hashmap_bucket_lock {
  struct bpf_spin_lock lock;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct ffkx_hashmap_bucket_lock);
  __uint(max_entries, 1);
} ffkx_hashmap_lock_map SEC(".maps");

uint32_t ffkx_hashmap_init_key_size;
uint32_t ffkx_hashmap_init_value_size;
uint32_t ffkx_hashmap_init_max_entries;

// Should be called from an init prog with the values above set
static __noinline int ffkx_hashmap_init(struct ffkx_hashmap *map, struct ffkx_hashmap_bucket *buckets, u32 nr_buckets) {
  reinterpret_cast(typeof(*map), map);
  reinterpret_cast(typeof(*buckets), buckets);

  map->max_key_size = ffkx_hashmap_init_key_size;
  map->max_value_size = ffkx_hashmap_init_value_size;
  map->max_entries = ffkx_hashmap_init_max_entries;

  if (!ffkx_hashmap_init_key_size || !ffkx_hashmap_init_value_size || !ffkx_hashmap_init_max_entries) {
    return -EINVAL;
  }

  if (!ffkx_pow_of_2(map->max_key_size) || !ffkx_pow_of_2(map->max_value_size)) {
    ffkx_log_error("key, value, or map->max entries are not power of 2");
    return -EINVAL;
  }

  map->buckets = buckets;
  // FIXME: nr_buckets is passed in to us, but we would want to do
  // pow_of_2(max_entries) here.
  map->nr_buckets = nr_buckets;
  map->hash_seed = bpf_get_prandom_u32();

  int i;
  bpf_for(i, 0, map->nr_buckets) {
    auto bucket = &map->buckets[i];
    cast(typeof(*bucket), bucket);
    // Initialize
    INIT_HLIST_NULLS_HEAD(&bucket->head, i);
  }

  // DEBUG: Validation
  bpf_for(i, 0, map->nr_buckets) {
    struct ffkx_hashmap_bucket *bucket = buckets + i;
    cast(typeof(*bucket), bucket);
    if (get_nulls_value(bucket->head.first) != i) {
      ffkx_log_error("Failed validation of bucket nulls values");
      return -EFAULT;
    }
  }
  return 0;
}

/// --- Implementation --- ///
///
/// Note that currently, the hash table provides no protection against parallel
/// updates to elements for the readers. This means that a value you are
/// attempting to read can be deleted and freed in parallel, and then reused for
/// an update from the allocator context and overwritten.
///
/// This is also why if we see an old element during update that we are
/// attempting to update, we reuse it directly and update the value.
///
/// If stronger protection is needed against parallel deletes, readers should
/// implement that on top of this hashmap, e.g. by marking a bit in the value
/// which logically deletes it, letting it stay in the hashmap until the RCU
/// grace period expires, and then issuing the physical delete operation on the
/// hashmap so that it is not messed up with.
///
/// This is mostly what the FFKX hashmap would do as well if it had to provide
/// stronger guarantees to readers, but that pessimizes our performance,
/// meanwhile the BPF hashmap makes no such guarantees anyway, which we want to
/// compare against, hence this implementation choice.

static __always_inline u32 ffkx_hashmap_hash(void *key, u32 key_size, u32 hash_seed) {
  if ((key_size % 4) == 0) {
    return jhash2(key, key_size >> 2, hash_seed);
  }
  return jhash(key, key_size, hash_seed);
}

static __always_inline struct hlist_nulls_head *ffkx_hashmap_get_bucket(struct ffkx_hashmap *map, u32 hash) {
  struct hlist_nulls_head *head;

  head = &map->buckets[hash & (map->nr_buckets - 1)].head;
  cast(struct hlist_nulls_head, head);
  return head;
}

static struct bpf_spin_lock *ffkx_hashmap_lock_bucket(struct ffkx_hashmap *map, u32 hash) {
  struct ffkx_hashmap_bucket_lock *l;
  struct bpf_spin_lock *lock;

  hash &= (map->nr_buckets - 1);
  l = bpf_map_lookup_elem(&ffkx_hashmap_lock_map, &hash);
  if (!l) {
    return NULL;
  }
  bpf_spin_lock(&l->lock);
  return &l->lock;
}

static __always_inline struct ffkx_hashmap_elem *__ffkx_hashmap_elem_alloc(struct ffkx_hashmap *map, u32 hash,
                                                                           void *key, u32 key_size, void *value,
                                                                           u32 value_size,
                                                                           struct ffkx_hashmap_elem *old) {
  struct ffkx_hashmap_elem *elem;

  if (old) {
    // FIXME: In case we support atomic updates, this code needs updating, ala
    // BPF_F_LOCK style.
    //
    // We do not wait an RCU grace period when freeing old elements, therefore
    // readers can already observe corruption of data. More synchronization is
    // needed on top (e.g. RCU gp delaying deletes) to protect against this.
    //
    // This per-CPU cache optimization is only useful for homogenous key_size vs
    // value_size, otherwise enabling it unconditionally means wasting the same
    // amount of memory for every object in the hashmap.
    struct ffkx_hashmap_elem **q = &map->pcpu_elem_queue[bpf_get_smp_processor_id()];
    // FIXME: We can only cast to struct or void, so this hack is needed. Let's
    // try to be more permissive later.
    cast(
        struct { struct ffkx_hashmap_elem *p; }, q);
    if (*q) {
      // Pop the previous element. We do this swap with a third element to allow
      // us to gracefully add the element to the head while old is sitting in
      // the list, and then remove old from list (allowing it to be immediately
      // reused). But we can't atomically move something from back of the list
      // to the front, but only remove and add atomically, with movement across
      // lists observable by readers (nulls_value checks). Therefore, on the
      // same CPU, do remove and add gracefully, we use this third cached
      // element to act as our rendezvous point.
      auto p = *q;
      // Since we support key_sizes <= max_key_size, we must ensure the old
      // element has enough room for us. Note that we may mark the current
      // element has having less size than us during init, but it's fine as this
      // optimization is mostly relevant for same-sized key-value hashmaps.
      //
      // Otherwise, we hit the per-CPU or global allocator anyway.
      if (p->key_size < key_size || p->value_size < value_size) {
        goto do_malloc;
      }
      // Queue the old element since we popped the previous one.
      *q = old;
      // Finally, let's use p and init ourselves.
      elem = p;
      goto init;
    } else {
      // Queue is empty, queue an element for next update.
      *q = old;
      // ... and let's do malloc.
      goto do_malloc;
    }
  }
do_malloc:
  elem = ffkx_malloc(sizeof(*elem) + ffkx_round_up(key_size, 8) + value_size);
  type_cast(typeof(*elem), elem);
  if (!elem) {
    return NULL;
  }
  // Let's not reinit the elem->node, as our allocator might host elements that
  // are possibly live in the list (or being read in parallel). hlist_add_rcu
  // will take care of proper assignment.

  // Init is placed here, since on reusing an element, we reuse its node values,
  // and simply add it to the table again. Assignments to next will be RCU
  // friendly, so no need to worry about atomicity.
init:
  // Do WRITE_ONCE for hash, key_size, and value_size, since they be read by
  // parallel readers. RCU safe list lookup does READ_ONCE/WRITE_ONCE too.
  // Why worry about parallel readers? Well, elem could be an old element from
  // the per-CPU cache of the hashmap itself, alive and well sitting in the
  // hashmap.
  FFKX_WRITE_ONCE(elem->hash, hash);
  FFKX_WRITE_ONCE(elem->key_size, key_size);
  FFKX_WRITE_ONCE(elem->value_size, value_size);

  char *elem_key = elem->buf;
  cast(void, elem_key);
  bpf_ffkx_memcpy(ffkx_conv_hptr(elem_key), key, key_size);
  // Align to 8 byte boundary
  char *elem_value = elem->buf + ffkx_round_up(key_size, 8);
  cast(void, elem_value);
  bpf_ffkx_memcpy(ffkx_conv_hptr(elem_value), value, value_size);
  return elem;
}

// Unsafe if lock is not taken.
static __always_inline struct ffkx_hashmap_elem *__ffkx_hashmap_lookup_unsafe(struct hlist_nulls_head *head, u32 hash,
                                                                              void *key, u32 key_size) {
  struct ffkx_hashmap_elem *l;
  struct hlist_nulls_node *n;

  hlist_nulls_for_each_entry_rcu(l, n, head, node) {
    // Hash does not match, look for next item
    if (FFKX_READ_ONCE(l->hash) != hash) {
      continue;
    }
    // If a key_size constraint is passed  (!0), then use it to avoid memcmp
    if (key_size && FFKX_READ_ONCE(l->key_size) != key_size) {
      continue;
    }
    char *elem_key = l->buf;
    cast(void, elem_key);
    if (bpf_ffkx_memequal(ffkx_conv_hptr(elem_key), key, key_size)) {
      return l;
    }
  }
  return NULL;
}

// Safe without lock, with RCU protection.
static __always_inline struct ffkx_hashmap_elem *__ffkx_hashmap_lookup_rcu(struct hlist_nulls_head *head, u32 hash,
                                                                           void *key, u32 key_size, u32 nr_buckets) {
  struct ffkx_hashmap_elem *l;
  struct hlist_nulls_node *n;

  ffkx_loop {
    hlist_nulls_for_each_entry_rcu(l, n, head, node) {
      // Hash does not match, look for next item
      if (FFKX_READ_ONCE(l->hash) != hash) {
        continue;
      }
      // If a key_size constraint is passed  (!0), then use it to avoid memcmp
      if (key_size && FFKX_READ_ONCE(l->key_size) != key_size) {
        continue;
      }
      char *elem_key = l->buf;
      cast(void, elem_key);
      if (bpf_ffkx_memequal(ffkx_conv_hptr(elem_key), key, key_size)) {
        return l;
      }
    }
    u32 mask = nr_buckets - 1;
    // If we didn't race during list traversal with a concurrent deletion,
    // let's break the loop and return. Otherwise, let's retry the lookup
    // procedure.
    if (get_nulls_value(n) != (hash & mask)) {
      continue;
    }
    break;
  }
  return NULL;
}

static __always_inline void *ffkx_hashmap_lookup(struct ffkx_hashmap *map, void *key, u32 key_size) {
  struct hlist_nulls_head *head;
  struct ffkx_hashmap_elem *l;
  void *value;
  u32 hash;

  // Buffer size needs to be passed in.
  if (!key_size || key_size > map->max_key_size) {
    return NULL;
  }

  hash = ffkx_hashmap_hash(key, key_size, map->hash_seed);
  head = ffkx_hashmap_get_bucket(map, hash);

  l = __ffkx_hashmap_lookup_rcu(head, hash, key, key_size, map->nr_buckets);
  if (!l) {
    return NULL;
  }
  value = l->buf + ffkx_round_up(key_size, 8);
  cast(void, value);
  return value;
}

static __always_inline struct ffkx_hashmap_elem *ffkx_hashmap_lookup_redis_elem(struct ffkx_hashmap *map, void *key,
                                                                                u32 key_size, u32 hash) {
  struct hlist_nulls_head *head;
  struct ffkx_hashmap_elem *l;
  void *value;

  // Buffer size needs to be passed in.
  if (!key_size || key_size > map->max_key_size) {
    return NULL;
  }

  head = ffkx_hashmap_get_bucket(map, hash);

  l = __ffkx_hashmap_lookup_rcu(head, hash, ffkx_conv_hptr(key), key_size, map->nr_buckets);
  if (!l) {
    return NULL;
  }
  return l;
}

static __always_inline void *ffkx_hashmap_lookup_redis(struct ffkx_hashmap *map, void *key, u32 key_size, u32 hash) {
  struct ffkx_hashmap_elem *l;
  void *value;

  l = ffkx_hashmap_lookup_redis_elem(map, key, key_size, hash);
  if (!l) return NULL;
  value = l->buf + ffkx_round_up(key_size, 8);
  cast(void, value);
  return value;
}

// FIXME: We need to support the case where value must be updated atomically.
// For now, parallel readers must implement some way of detecting updates in
// parallel to the object itself.
static __always_inline int ffkx_hashmap_update(struct ffkx_hashmap *map, void *key, u32 key_size, void *value,
                                               u32 value_size) {
  struct ffkx_hashmap_elem *elem, *old;
  struct hlist_nulls_head *head;
  u32 hash;
  int ret;

  if (!key_size || key_size > map->max_key_size || !value_size || value_size > map->max_value_size) {
    return -EINVAL;
  }

  hash = ffkx_hashmap_hash(key, key_size, map->hash_seed);
  head = ffkx_hashmap_get_bucket(map, hash);

  // TODO(kkd): Switch to our spin locks
  struct bpf_spin_lock *lock = ffkx_hashmap_lock_bucket(map, hash);
  if (!lock) {
    return -EFAULT;
  }

  // Lookup the old element, since we can reuse it.
  old = __ffkx_hashmap_lookup_unsafe(head, hash, key, key_size);

  // Allocate and initialize element before taking the lock, so that we don't
  // contend unecessarily. Pass in old (which is consumed if not NULL), so that
  // we can reuse the old allocation.
  //
  // Note that the we reuse old is to queue it locally on the CPU if the queue
  // is empty. If not, we remove the item in the queue and move in old, keeping
  // the queue size as one. More importantly, this means that we reuse old
  // elements on the same CPU without RCU grace periods, but we have this queue
  // logic to allow us to insert an element to the head (allowing it to be found
  // faster) while we remove the old from the list and queue it.
  //
  // Directly updating old would mean that it would have to stay where it is in
  // the list.
  elem = __ffkx_hashmap_elem_alloc(map, hash, key, key_size, value, value_size, old);
  if (!elem) {
    bpf_spin_unlock(lock);
    return -ENOMEM;
  }
  hlist_nulls_add_head_rcu(&elem->node, head);
  // We add and publish the new element to the head, so that is found first
  // during search, while we concurrently delete the old element.
  if (old) {
    hlist_nulls_del_rcu(&old->node);
  }
  bpf_spin_unlock(lock);
  return 0;
}

// FIXME: We need to support the case where value must be updated atomically.
// For now, parallel readers must implement some way of detecting updates in
// parallel to the object itself.
static __always_inline int ffkx_hashmap_update_redis(struct ffkx_hashmap *map, void *key, u32 key_size, void *value,
                                                     u32 value_size, u32 hash) {
  struct ffkx_hashmap_elem *elem, *old;
  struct hlist_nulls_head *head;
  int ret;

  if (!key_size || key_size > map->max_key_size || !value_size || value_size > map->max_value_size) {
    return -EINVAL;
  }

  head = ffkx_hashmap_get_bucket(map, hash);
  // FIXME: Disable for redis, but introduce proper accessors instead of this shit
  /*
  // TODO(kkd): Switch to our spin locks
  struct bpf_spin_lock *lock = ffkx_hashmap_lock_bucket(map, hash);
  if (!lock) {
    return -EFAULT;
  }
*/
  // Lookup the old element, since we can reuse it.
  old = __ffkx_hashmap_lookup_unsafe(head, hash, ffkx_conv_hptr(key), key_size);

  // Don't convert value pointer, as it comes from stack
  elem = __ffkx_hashmap_elem_alloc(map, hash, ffkx_conv_hptr(key), key_size, value, value_size, old);
  if (!elem) {
    // FIXME: See comment about Redis
    // bpf_spin_unlock(lock);
    return -ENOMEM;
  }
  hlist_nulls_add_head_rcu(&elem->node, head);
  // We add and publish the new element to the head, so that is found first
  // during search, while we concurrently delete the old element.
  if (old) {
    hlist_nulls_del_rcu(&old->node);
  }
  // FIXME:Likewise
  // bpf_spin_unlock(lock);
  return 0;
}

static __always_inline int ffkx_hashmap_delete(struct ffkx_hashmap *map, void *key, u32 key_size) {
  struct ffkx_hashmap_elem *elem;
  struct hlist_nulls_head *head;
  int ret = 0;
  u32 hash;

  if (!key_size || key_size > map->max_key_size) {
    return -EINVAL;
  }

  hash = ffkx_hashmap_hash(key, key_size, map->hash_seed);
  head = ffkx_hashmap_get_bucket(map, hash);

  // TODO(kkd): Switch to our spin locks
  struct bpf_spin_lock *lock = ffkx_hashmap_lock_bucket(map, hash);
  if (!lock) {
    return -EFAULT;
  }

  elem = __ffkx_hashmap_lookup_unsafe(head, hash, key, key_size);
  if (elem) {
    hlist_nulls_del_rcu(&elem->node);
  } else {
    ret = -ENOENT;
  }

  bpf_spin_unlock(lock);
  ffkx_free(elem);

  return ret;
}

#endif
