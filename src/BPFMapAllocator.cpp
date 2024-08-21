// SPDX-License-Identifier: MIT

#include <absl/status/statusor.h>
#include <absl/strings/str_format.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <jemalloc/jemalloc.h>
#include <sys/mman.h>

#include <BPFMapAllocator.hpp>
#include <Utility.hpp>
#include <limits>
#include <string>

namespace ffkx {
namespace bpf {

namespace {

inline MapAllocator *curr_ma;

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

MapAllocator::~MapAllocator() {
  if (!addr_) {
    return;
  }
  int ret = munmap(addr_, size_);
  if (ret < 0) {
    std::cerr << "Failed to munmap map allocator region. Skipping!\n";
  }
}

// Use a simple bump allocation scheme, and round up offset to always be 8 byte
// aligned. Once an allocation is made, it will always just be reused, never
// freed, therefore, we don't care about fitting allocations into holes as
// technically there are never going to be any.
absl::StatusOr<void *> MapAllocator::Reserve(size_t size) {
  size_t remaining_size = size_ - offset_;
  if (size > remaining_size) {
    return absl::ResourceExhaustedError(absl::StrFormat("Requested allocation size (%zu) is too big.", size));
  }
  size = util::RoundUpTo<8>(size);
  void *ptr = static_cast<char *>(addr_) + offset_;
  offset_ += size;
  return ptr;
}

absl::StatusOr<void *> MapAllocator::AllocateNew(size_t size) {
  curr_ma = this;
  // TODO(kkd): Figure out tcache usage, for now pass this flag
  void *p = mallocx(size, MALLOCX_ARENA(arena_ind_) | MALLOCX_TCACHE_NONE);
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

// Perform a set of sanity checks for the map we are going to use to serve the
// bump allocations. First, ensure that we don't hit kernel imposed limits for
// the requested region size. Next, ensure that size is a page size multiple, so
// that we allocate some N pages for the map. Finally, also ensure that the map
// value size is already a page size, so that we just simply bump the
// max_entries instead of having to fiddle with the value size (and thus type,
// which causes problems with BTF information attached to it).
absl::StatusOr<MapAllocator> MapAllocator::MakeNew(size_t size) {
  if (size % 4096) {
    return absl::InvalidArgumentError(
        absl::StrFormat("Requested allocation size (%zu) is not a multiple of page size", size));
  }
	// Power of 2 check
/*
  struct bpf_map *m = map.Get();
  int ret = bpf_map__set_max_entries(m, 1);
  if (ret < 0) {
    return absl::ErrnoToStatus(errno, "Failed to set maximum entry as 1 for BPF map for map allocator");
  }

  ret = bpf_map__set_value_size(m, size);
  if (ret < 0) {
    return absl::ErrnoToStatus(errno, "Failed to set value size for BPF map for map allocator");
  }
*/
  return MapAllocator(nullptr, size, -1);
}

absl::Status MapAllocator::CreateMapping(const Map& map) {
  int map_fd = map.GetRawFd();
  void *addr = mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
  if (addr == MAP_FAILED) {
    return absl::ErrnoToStatus(errno, "Failed to mmap BPF map fd for map allocator");
  }
  addr_ = addr;

  return CreateMapArena();
}

absl::Status MapAllocator::SetMapping(void *addr) {
  if (addr_) {
    return absl::AlreadyExistsError("Owned mapping already exists for BPF map\n");
  }
  addr_ = addr;
  return CreateMapArena();
}

// The reason we have to create jemalloc arena and assign the index on creation
// of the mapping address, is because the mapping address is also used to serve
// arena-specific allocation requests before actual objects are allocated. This
// will end up failing if it is done before we have set up the BPF map
// allocator mapping.
absl::Status MapAllocator::CreateMapArena() {
  curr_ma = this;

  unsigned int arena_ind = -1;
  size_t arena_ind_size = sizeof(arena_ind);
  auto *hooks = &bpf_arena_extent_hooks;
  // Returns 0 on success, positive error value on failure
  int ret = mallctl("arenas.create", static_cast<void *>(&arena_ind), &arena_ind_size, static_cast<void *>(&hooks),
                    sizeof(extent_hooks_t *));
  if (ret) {
    errno = ret;
    return absl::ErrnoToStatus(errno, "Failed to create new arena for BPF map");
  }
  arena_ind_ = arena_ind;
  curr_ma = nullptr;
  return absl::OkStatus();
}

}  // namespace bpf
}  // namespace ffkx
