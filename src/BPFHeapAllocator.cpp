// SPDX-License-Identifier: MIT

#include <absl/status/statusor.h>
#include <absl/strings/str_format.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <jemalloc/jemalloc.h>
#include <sys/mman.h>

#include <BPFHeapAllocator.hpp>
#include <Utility.hpp>

namespace ffkx {
namespace bpf {

namespace {

thread_local inline HeapAllocator *curr_ma;

void *bpf_arena_extent_alloc(extent_hooks_t *hooks [[maybe_unused]], void *new_addr [[maybe_unused]], size_t size,
                             size_t alignment [[maybe_unused]], bool *zero, bool *commit [[maybe_unused]],
                             unsigned arena_ind [[maybe_unused]]) {
  if (!curr_ma) {
    return nullptr;
  }
  auto res = curr_ma->Reserve(size);
  if (!res.ok()) {
    return nullptr;
  }
  void *p = res.value();
  if (*zero) {
    memset(p, 0, size);
  }
  return p;
}

struct extent_hooks_s bpf_arena_extent_hooks = {
    .alloc = bpf_arena_extent_alloc,
};

}  // namespace

// Use a simple bump allocation scheme, and round up offset to always be 8 byte
// aligned. Once an allocation is made, it will always just be reused, never
// freed, therefore, we don't care about fitting allocations into holes as
// technically there are never going to be any.
absl::StatusOr<void *> HeapAllocator::Reserve(size_t size) {
  size = util::RoundUpTo<8>(size);
  size_t remaining_size = size_ - offset_;
  if (size > remaining_size) {
    return absl::ResourceExhaustedError(absl::StrFormat("Requested allocation size (%zu) is too big.", size));
  }
  void *ptr = static_cast<char *>(addr_) + offset_;
  offset_ += size;
  return ptr;
}

// Perform a set of sanity checks for the heap we are going to use to serve the
// bump allocations. First, ensure that we don't hit kernel imposed limits for
// the requested region size. Next, ensure that size is a page size multiple, so
// that we allocate some N pages for the heap.
absl::StatusOr<HeapAllocator> HeapAllocator::MakeNew(Map map) {
  auto m = map.Get();
  size_t value_size = bpf_map__value_size(m);
  size_t max_entries = bpf_map__max_entries(m);
  size_t size = value_size * max_entries;

  if (size % 4096) {
    return absl::InvalidArgumentError(absl::StrFormat("Heap map size (%zu) is not a multiple of page size", size));
  }

  auto addr = bpf_map__heap_address(m);
  if (!addr) {
    return absl::NotFoundError("Cannot find base address of heap map\n");
  }
  // TODO(kkd): Power of 2 check
  HeapAllocator heap(addr, size, -1);
  auto res = heap.CreateHeapArena();
  if (!res.ok()) {
    return res;
  }
	// IMPORTANT:
	// Extract a page out of every heap, to avoid generating objects in the first
	// page, which confuses base SFI implementation as valid pointer may appear
	// NULL to program.
	(void)heap.AllocateNew(4096).value();
  return heap;
}

// The reason we have to create jemalloc arena and assign the index on creation
// of the mapping address, is because the heapping address is also used to
// serve arena-specific allocation requests before actual objects are allocated.
// This will end up failing if it is done before we have set up the BPF heap
// allocator heapping.
absl::Status HeapAllocator::CreateHeapArena() {
  curr_ma = this;

  unsigned int arena_ind = -1;
  size_t arena_ind_size = sizeof(arena_ind);
  auto *hooks = &bpf_arena_extent_hooks;
  // Returns 0 on success, positive error value on failure
  int ret = mallctl("arenas.create", static_cast<void *>(&arena_ind), &arena_ind_size, static_cast<void *>(&hooks),
                    sizeof(extent_hooks_t *));
  if (ret) {
    errno = ret;
    return absl::ErrnoToStatus(errno, "Failed to create new jemalloc arena for BPF heap");
  }
  arena_ind_ = arena_ind;
  curr_ma = nullptr;
  return absl::OkStatus();
}

absl::StatusOr<void *> HeapAllocator::AllocateNew(size_t size) {
  curr_ma = this;
  // TODO(kkd): Figure out tcache usage, for now pass this flag
	// TODO(kkd): Bug, mallocx returns bad memory area
  void *p = mallocx(size, MALLOCX_ARENA(arena_ind_) | MALLOCX_TCACHE_NONE);
	p = this->Reserve(size).value();
  if (p) {
    assert(reinterpret_cast<uintptr_t>(p) >= reinterpret_cast<uintptr_t>(addr_));
    assert(reinterpret_cast<uintptr_t>(p) < reinterpret_cast<uintptr_t>(addr_) + size_);
  }
  curr_ma = nullptr;
  if (!p) {
    return absl::ResourceExhaustedError("Failed to allocate memory using mallocx");
  }
  return p;
}

}  // namespace bpf
}  // namespace ffkx
