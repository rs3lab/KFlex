// SPDX-License-Identifier: MIT
#ifndef FFKX_BPF_MALLOC_HPP
#define FFKX_BPF_MALLOC_HPP

#include <ffkx_malloc.h>
#include <BPFHeapAllocator.hpp>

namespace ffkx {
namespace bpf {

class Malloc {
 public:
  explicit Malloc(HeapAllocator&& heap) : heap_(std::move(heap)) {}
  Malloc(const Malloc&) = delete;
  Malloc& operator=(const Malloc&) = delete;
  Malloc(Malloc&&) = default;
  Malloc& operator=(Malloc&&) = default;
  ~Malloc() = default;

 private:
  HeapAllocator heap_;
};

}  // namespace bpf
}  // namespace ffkx

#endif
