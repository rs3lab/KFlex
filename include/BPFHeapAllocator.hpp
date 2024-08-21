// SPDX-License-Identifier: MIT
#ifndef FFKX_BPF_HEAP_ALLOCATOR_HPP
#define FFKX_BPF_HEAP_ALLOCATOR_HPP

#include <absl/status/statusor.h>
#include <ffkx_malloc.h>

#include <BPF.hpp>

namespace ffkx {
namespace bpf {

class HeapAllocator {
 public:
  constexpr explicit HeapAllocator() : addr_(nullptr), size_(0), offset_(0), arena_ind_(-1) {}
  HeapAllocator(const HeapAllocator&) = delete;
  HeapAllocator& operator=(const HeapAllocator&) = delete;
  HeapAllocator(HeapAllocator&& m) noexcept {
    addr_ = std::exchange(m.addr_, nullptr);
    size_ = std::exchange(m.size_, 0);
    offset_ = std::exchange(m.offset_, 0);
  }
  HeapAllocator& operator=(HeapAllocator&& m) noexcept {
    if (this != &m) {
      addr_ = std::exchange(m.addr_, nullptr);
      size_ = std::exchange(m.size_, 0);
      offset_ = std::exchange(m.offset_, 0);
    }
    return *this;
  }
  ~HeapAllocator() = default;

  void *BaseAddress() const { return addr_; }

  unsigned int GetJemallocArenaIndex() const { return arena_ind_; }

  template <typename T = void>
  [[nodiscard]] absl::StatusOr<T *> Allocate(size_t size = sizeof(T)) {
    auto p = AllocateNew(size);
    if (!p.ok()) {
      return p.status();
    }
    return static_cast<T *>(p.value());
  }

  [[nodiscard]] absl::StatusOr<void *> Reserve(size_t size);

  static absl::StatusOr<HeapAllocator> MakeNew(Map map);

 private:
  HeapAllocator(void *addr, size_t size, unsigned int arena_ind)
      : addr_(addr), size_(size), offset_(0), arena_ind_(arena_ind) {}

  absl::Status CreateHeapArena();

  [[nodiscard]] absl::StatusOr<void *> AllocateNew(size_t size);

  void *addr_;
  size_t size_;
  size_t offset_;
  unsigned int arena_ind_;
};

inline constexpr size_t MallocIndexToSize[FFKX_MALLOC_SIZE_CLASS] = {16,  32,  64,   96,   128, 192,
                                                                     256, 512, 1024, 2048, 4096};

inline size_t MallocSizeToIndex(size_t size) {
  assert(size <= 4096);
  for (int i = 0; i < FFKX_MALLOC_SIZE_CLASS; i++) {
    if (size <= MallocIndexToSize[i]) {
      return i;
    }
  }
  assert(0);
  return -1;
}

template <typename F>
inline absl::StatusOr<struct ffkx_malloc_cache *> PopulateMallocCache(bpf::HeapAllocator& ma, F conv,
                                                                      struct ffkx_malloc_cache *cache, int capacity,
                                                                      int idx = -1) {
  memset(cache, 0, sizeof(*cache));
  for (int i = 0; i < FFKX_MALLOC_SIZE_CLASS; i++) {
    struct ffkx_malloc_size_cache *scache = &cache->sizes[i];
    // Request to only populate a single size class
    if (idx != -1 && i >= idx) {
      continue;
    }
    for (int j = 0; j < capacity; j++) {
      // Allocate one object with a header
      auto p = ma.template Allocate<struct ffkx_malloc_object_hdr>(sizeof(struct ffkx_malloc_object_hdr) +
                                                                   MallocIndexToSize[i]);
      if (!p.ok()) {
        return p.status();
      }
      auto ptr = p.value();
      ptr->index = i;

      // Link into the list, also convert pointer value
      ptr->next = conv(scache->head);
      auto cptr = reinterpret_cast<struct ffkx_slist_head *>(ptr);
      scache->head = conv(cptr);
      if (scache->count) {
        assert(ptr->next);
      }
      if (!ptr->next) {
        scache->tail = conv(cptr);
      }
      // Set splice_head at halfway mark, capacity is power of two
      // Only relevant for per-CPU lists, global doesn't care right now.
      // The element next to splice_head is gone, so set at the current
      // one.
      assert((capacity % 2) == 0);
      if (scache->count == ((capacity / 2) - 1)) {
        scache->splice_head = conv(cptr);
      }
      scache->count++;
    }
    assert(scache->count == capacity);
  }
  return cache;
}

// transparent decides if heap transparency will be enabled with user space,
// this incurs extra overhead as kernel will perform pointer translations
// when writing back data to the heap (at pointer locations).
//
// capacity decides how many items are present in the per-CPU and global caches,
// global is typically per-CPU * NR_CPUS to have a backup for all CPUs.
//
// no_global will disable adding anything to the global pool
//
// cpus = -1 is default, which means filling all CPUs and global list with
// capacity and capacity * NR_CPUS respectively.
// cpus is the maximum CPU number whose list must be filled, hence cpus = 1
// only fills CPU 0's cache.
//
// cpus = 0 thus disabled per-CPU caching, and would require global pool to be
// filled for any memory.
//
// index decides if only a specific index is populated in the above
// configurations. TODO: This can be made a vector/set to populate multiple,
// when a use case comes up. Can be used to create object arenas on the heap.
//
//
// // TODO(kkd): Right now heap and malloc cache are tied together, but these
// can be separated.

enum StateGlobal : bool {
  kNoGlobal = false,
  kGlobal = true,
};

enum StatePerCPU : int {
  kNoPerCPU = 0,
  kPerCPU = 1,
  kOneCPU = 2,
};

template <typename S>
absl::StatusOr<bpf::HeapAllocator> CreateHeapAllocator(S& skel, int cpu_capacity = FFKX_MALLOC_PCPU_HIGH_WATERMARK,
                                                       int capacity = FFKX_MALLOC_PCPU_HIGH_WATERMARK,
                                                       StateGlobal global = kGlobal, StatePerCPU per_cpu = kPerCPU,
                                                       int index = -1) {
  assert(!(global == kNoGlobal && per_cpu == kNoPerCPU));
  if (per_cpu == kOneCPU) {
    assert(global == kNoGlobal);
  }

  auto mares = bpf::HeapAllocator::MakeNew(bpf::Map(skel->maps.heap));
  if (!mares.ok()) {
    return mares;
  }

  auto ma = std::move(mares.value());

  // Update size class mappings
  for (size_t i = 0, j = 0; i < FFKX_MALLOC_SIZE_MAP_SZ; i++) {
    assert(j < FFKX_MALLOC_SIZE_CLASS);
    skel->bss->ffkx_malloc_size_map[i] = j;
    // This is the max i that can be satisfied with j class.
    if (i == MallocIndexToSize[j]) {
      j++;
    }
  }

  // Obtain the kernel base address
  struct bpf_test_run_opts opts;
  INIT_LIBBPF_OPTS(opts);
  char buf[32];
  opts.data_in = static_cast<void *>(buf);
  opts.data_size_in = sizeof(buf);
  opts.repeat = 1;

  int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.ffkx_malloc_heap_base), &opts);
  if (ret || opts.retval) {
    return absl::InvalidArgumentError("Can't run program to obtain heap kbase");
  }

  auto translate = [&](auto ptr) {
    if (!ptr) {
      return ptr;
    }
    auto kbase = skel->bss->ffkx_malloc_heap_kbase;
    uint64_t ubase = reinterpret_cast<uint64_t>(ma.BaseAddress());
    assert(!(ubase & skel->bss->ffkx_malloc_heap_kmask));
    return reinterpret_cast<decltype(ptr)>((reinterpret_cast<uint64_t>(ptr) - ubase) + kbase);
  };

  int cpus = per_cpu == kOneCPU ? 1 : libbpf_num_possible_cpus();
  if (per_cpu == kPerCPU || per_cpu == kOneCPU) {
    auto pcpu_cache = ma.Allocate<struct ffkx_malloc_cache>(sizeof(struct ffkx_malloc_cache) * cpus);
    if (!pcpu_cache.ok()) {
      return pcpu_cache.status();
    }
    for (auto i = 0; i < cpus; i++) {
      auto p = PopulateMallocCache(ma, translate, pcpu_cache.value() + i, cpu_capacity, index);
      if (!p.ok()) {
        return p.status();
      }
    }
    skel->bss->ffkx_malloc_caches.pcpu = translate(pcpu_cache.value());
  }
  // We don't want global lists to have anything.
  if (global == kNoGlobal) {
    return ma;
  }
  auto global_cache = ma.Allocate<struct ffkx_malloc_cache>(sizeof(struct ffkx_malloc_cache));
  if (!global_cache.ok()) {
    return global_cache.status();
  }
  auto p = PopulateMallocCache(ma, translate, global_cache.value(), capacity, index);
  if (!p.ok()) {
    return p.status();
  }
  skel->bss->ffkx_malloc_caches.global = translate(global_cache.value());
  return ma;
}

// Creates both per-CPU and global heaps
template <typename S>
absl::StatusOr<bpf::HeapAllocator> CreateDefaultHeap(S& skel, int capacity, int index = -1) {
  return CreateHeapAllocator(skel, FFKX_MALLOC_PCPU_HIGH_WATERMARK, capacity, kGlobal, kPerCPU, index);
}

template <typename S>
absl::StatusOr<bpf::HeapAllocator> CreateOneCPUHeap(S& skel, int capacity, int index = -1) {
  return CreateHeapAllocator(skel, capacity, 0, kNoGlobal, kOneCPU, index);
}

template <typename S>
absl::StatusOr<bpf::HeapAllocator> CreateGlobalHeap(S& skel, int capacity, int index = -1) {
  return CreateHeapAllocator(skel, 0, capacity, kGlobal, kNoPerCPU, index);
}

// kPerCPu and kNoGlobal combination is bad (no protection against imbalance),
// hence not exposed or allowed.

}  // namespace bpf
}  // namespace ffkx

#endif
