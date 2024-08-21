// SPDX-License-Identifier: MIT
#ifndef FFKX_MAP_ALLOCATOR_HPP
#define FFKX_MAP_ALLOCATOR_HPP

#include <absl/status/statusor.h>

#include <BPF.hpp>

// BPF Map Allocator
//
// This class implements a simple bump allocator to preallocate objects that are
// to be shared between BPF programs and userspace. TODO(kkd): Implement and use
// allocator map using bpf_memalloc to avoid preallocation with array map.
//
// We create and use a BPF array map as a quasi allocator, by mmap'ing the data
// region into userspace. We then require the userspace to provide a size
// argument to resize and mmap the region, and enforce that it is a multiple of
// page size (hardcoded as 4096 for now). Each map element is page sized, and
// the max_entries decides the total number of pages.
//
// The BPF program will figure out the base address of the vmalloc'd range in
// kernel, and then the base address of the mmap'd region in userspace, and then
// perform pointer translation whenever it performs an access. Each pointer load
// thus needs to account for the mapping offset difference properly translate
// the pointers from userspace to the kernel equivalent.
//
// Once the base difference is cached, it shouldn't be a huge penalty, but cost
// shifting heuristics can be done if it turns out to be a problem, such as:
//	- Userspace figuring out the kernel addresses and performing conversion, to
//	not penalize read path.
//  - Using indexes instead of pointers to allow base relative addressing in
//  both userspace and kernel space.

namespace ffkx {
namespace bpf {

class MapAllocator {
 public:
  constexpr explicit MapAllocator() : addr_(nullptr), size_(0), offset_(0), arena_ind_(-1) {}
  MapAllocator(const MapAllocator&) = delete;
  MapAllocator& operator=(const MapAllocator&) = delete;
  MapAllocator(MapAllocator&& m) noexcept {
    addr_ = std::exchange(m.addr_, nullptr);
    size_ = std::exchange(m.size_, 0);
    offset_ = std::exchange(m.offset_, 0);
  }
  MapAllocator& operator=(MapAllocator&& m) noexcept {
    if (this != &m) {
      addr_ = std::exchange(m.addr_, nullptr);
      size_ = std::exchange(m.size_, 0);
      offset_ = std::exchange(m.offset_, 0);
    }
    return *this;
  }
  ~MapAllocator();

  void *BaseAddressOfMapping() const { return addr_; }

  unsigned int GetJemallocArenaIndex() const { return arena_ind_; }

  absl::Status CreateMapping(const Map& map);

  absl::Status SetMapping(void *addr);

  [[nodiscard]] absl::StatusOr<void *> Reserve(size_t size);

  [[nodiscard]] absl::StatusOr<void *> AllocateNew(size_t size);

  static absl::StatusOr<MapAllocator> MakeNew(size_t size);

 private:
  MapAllocator(void *addr, size_t size, unsigned int arena_ind)
      : addr_(addr), size_(size), offset_(0), arena_ind_(arena_ind) {}

  absl::Status CreateMapArena();

  void *addr_;
  size_t size_;
  size_t offset_;
  unsigned int arena_ind_;
};

}  // namespace bpf
}  // namespace ffkx

#endif
