// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_MALLOC_H
#define FFKX_BPF_FFKX_MALLOC_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
// clang-format off
#include <vmlinux.h>
#endif

#define FFKX_MALLOC_SIZE_CLASS (11)
#define FFKX_MALLOC_SIZE_MAP_SZ (4097)
#define FFKX_MALLOC_NR_CACHE (64)  // NR_CPUS
#define FFKX_MALLOC_PCPU_HIGH_WATERMARK (512)
#define FFKX_MALLOC_PCPU_HIGH_WATERMARK_HALF (FFKX_MALLOC_PCPU_HIGH_WATERMARK >> 1)
#define FFKX_MALLOC_PCPU_LOW_WATERMARK (64)
#define FFKX_MALLOC_GLOBAL_HIGH_WATERMARK (FFKX_MALLOC_PCPU_HIGH_WATERMARK *FFKX_MALLOC_NR_CACHE)
#define FFKX_MALLOC_GLOBAL_LOW_WATERMARK (FFKX_MALLOC_PCPU_LOW_WATERMARK *FFKX_MALLOC_NR_CACHE)

struct ffkx_malloc_object_hdr {
  struct ffkx_slist_head *next;
  uint64_t index;
};

struct ffkx_slist_head {
  struct ffkx_slist_head *next;
};

struct ffkx_malloc_size_cache {
  struct ffkx_slist_head *head;
  struct ffkx_slist_head *tail;
  struct ffkx_slist_head *splice_head;
  int count;
};

// This is a cache of FFKX_MALLOC_SIZE_CLASS size classes
// 16 32 64 96 128 192 256 512 1024 2048 4096
// It can be kept per-CPU, and one is global to allow efficiency of allocations
// in cases of persistent imbalance.
struct ffkx_malloc_cache {
  struct ffkx_malloc_size_cache sizes[FFKX_MALLOC_SIZE_CLASS];
};

struct ffkx_malloc_caches {
	// Points to an array indexed by CPU
	struct ffkx_malloc_cache *pcpu;
	// Points to a single global instance
	struct ffkx_malloc_cache *global;
};

#ifdef __cplusplus
}
#endif

#endif
