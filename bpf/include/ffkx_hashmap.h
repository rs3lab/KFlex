// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_HASHMAP_H
#define FFKX_BPF_FFKX_HASHMAP_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {

struct hlist_nulls_node {
  struct hlist_nulls_node *next;
  struct hlist_nulls_node **pprev;
};

struct hlist_nulls_head {
  struct hlist_nulls_node *first;
};

#else
#include <vmlinux.h>
// Since we dump a type in C++ mode, let's ensure atleast size is same.
_Static_assert(sizeof(struct hlist_nulls_node) == 16, "Size mismatch for hlist_nulls_node");
_Static_assert(sizeof(struct hlist_nulls_head) == 8, "Size mismatch for hlist_nulls_head");
#endif

struct ffkx_hashmap_bucket {
  struct hlist_nulls_head head;
};

struct ffkx_hashmap {
  // Hashmap attributes
  uint32_t max_key_size;
  uint32_t max_value_size;
  uint32_t max_entries;
  // Bucket lists
  uint32_t nr_buckets;
  uint32_t hash_seed;
  struct ffkx_hashmap_bucket *buckets;
  struct ffkx_hashmap_elem *pcpu_elem_queue[0];
};

struct ffkx_hashmap_elem {
  struct hlist_nulls_node node;
  uint32_t hash;
  uint32_t key_size;
  uint32_t value_size;
  char buf[0] __attribute__((aligned(8)));
};

#ifdef __cplusplus
}
#endif

#endif
