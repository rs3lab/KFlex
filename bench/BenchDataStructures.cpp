// SPDX-License-Identifier: MIT
// clang-format off
#include <ffkx_malloc.h>
// clang-format on
#include <absl/status/statusor.h>
#include <absl/strings/str_format.h>
// FIXME: Share properly
#define MAX_SKIPLIST_HEIGHT 32
#define CS_ROWS 4
#define CS_COLUMNS 512

#define HASHFN_N CS_ROWS
#define COLUMNS CS_COLUMNS

struct countsketch {
  uint32_t values[HASHFN_N][COLUMNS];
};

struct countmin {
  uint32_t values[HASHFN_N][COLUMNS];
};

struct ffkx_skiplist_elem {
  uint32_t height;
  uint32_t key_size;
  struct ffkx_skiplist_elem *next[MAX_SKIPLIST_HEIGHT];
  char buf[];
};
struct rb_root {
  struct rb_node *rb_node;
};
struct rb_root_cached {
  struct rb_root rb_root;
  struct rb_node *rb_leftmost;
};
struct ffkx_rb_root_cached;
#include <bench_data_structures.skel.h>
#include <benchmark/benchmark.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ffkx_hashmap.h>

#define BPF_F_HEAP_TRANS (1U << 19)

#include <BPF.hpp>
#include <BPFHeapAllocator.hpp>
#include <BenchRandomUtil.hpp>
#include <vector>

int kBenchmarkSize = 1'00'000;
int kBenchmarkIterations = kBenchmarkSize;  // 1'000'000;

/// --- Data Structures Benchmark --- ///
///
/// This benchmark is primarily meant to perform microbenchmarking of data
/// structure operations, stress testing under various synthetic workloads, and
/// measuring the scalability of FFKX implementations against their existing
/// contemporary counterparts.
///
/// We use fixtures to generate distributions over which we test various data
/// structures.

using namespace ffkx;

namespace {

// Generate the distributions for all benchmark runs at once.
const std::vector<uint64_t> U_dist_ = bench::GenerateUniformRandomDistribution(kBenchmarkSize);
const std::vector<uint64_t> Z_dist_ = bench::GenerateZipfianSkewedDistribution(kBenchmarkSize);

enum ConfigState : int {
  kAfterOpen = 0,
  kAfterLoad = 1,
};

template <typename T>
using Config = void (*)(benchmark::State&, T&, ConfigState);

enum Distribution {
  Uniform,
  Zipfian,
};

std::vector<uint64_t> CreateKeyValueBuffer(benchmark::State& state, uint64_t key, size_t key_size, size_t value_size) {
  if ((key_size % sizeof(uint64_t)) || (value_size % sizeof(uint64_t))) {
    std::string msg = "Failed to create key value buffer, not multiples of 8";
    state.SkipWithError(msg.data());
    assert(0);
  }
  auto cnt = (key_size + value_size) / sizeof(uint64_t);

  std::vector<uint64_t> buf;
  while (cnt--) {
    buf.push_back(key);
  }
  return buf;
}

int RunProg(benchmark::State& state, struct bpf_program *prog, void *data_in, size_t data_in_size, void *data_out,
            size_t data_out_size, bool many = false) {
  struct bpf_test_run_opts opts;
  INIT_LIBBPF_OPTS(opts);
	(void)many;

  opts.data_in = data_in;
  opts.data_size_in = data_in_size;
  opts.data_out = data_out;
  opts.data_size_out = data_out_size;
  opts.repeat = 1;

  // Always ensure we do CPU 0 for single threaded bench
  if (state.threads() == 1) {
    opts.flags = BPF_F_TEST_RUN_ON_CPU;
    opts.cpu = 0;
  }

  int ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
  if (ret || opts.retval) {
    state.SkipWithError(
        absl::StrFormat("Failed to run prog %s: ret=%d retval=%d", bpf_program__name(prog), ret, opts.retval));
    return ret;
  }
  return 0;
}

// The order of operations is as follows:
//
// Set up
// Open skeleton
// Config after open
// Load skeleton
// Config after load
//
// Run (with possibly multiple threads)
// If lookup or delete bench, populate data structure
// Benchmark
//
// Teardown
// Collect throughput

template <typename T, Config<bpf::Skeleton<T>> F, Distribution D, bool kTranslation = false>
class SkeletonFixture : public benchmark::Fixture {
 public:
  virtual void SetUp(benchmark::State& state) override final {
    // Let's only do set up on one thread. Other threads will race ahead to
    // benchmark start, but all functions in that path should perform this
    // check.
    if (state.thread_index() != 0) {
      return;
    }

    auto res = skel_.Open();
    if (!res.ok()) {
      state.SkipWithError("Failed to open skeleton: " + res.ToString());
      return;
    }

    if (kTranslation) {
      // FIXME: Ensure we rely on the header definition of BPF_F_HEAP_TRANS,
      // since it may change on rebasing upstream.
      int ret = bpf_map__set_map_flags(skel_->maps.heap, BPF_F_HEAP_TRANS);
      if (ret < 0) {
        state.SkipWithError("Failed to set transparency flag for heap");
        return;
      }
    }

    auto key_size = state.range(0);
    auto value_size = state.range(1);

    // Set the configuration parameters.
    skel_->rodata->bench_data_structures_key_size = key_size;
    skel_->rodata->bench_data_structures_value_size = value_size;
    skel_->rodata->bench_data_structures_max_entries = kBenchmarkSize;
    skel_->rodata->bench_data_structures_multithreaded = state.threads() > 1;

    // Configure the skeleton before we load it into the kernel.
    F(state, skel_, kAfterOpen);

    res = skel_.Load();
    if (!res.ok()) {
      state.SkipWithError("Failed to load skeleton: " + res.ToString());
      return;
    }

    // Configure the skeleton after it's loaded into the kernel.
    F(state, skel_, kAfterLoad);
  }

  virtual void TearDown(benchmark::State& state) override final {
    // Let's only do teardown on one thread.
    if (state.thread_index() != 0) {
      return;
    }
    // FIXME FIXME FIXME fails for sketch
    // assert(skel_->bss->bench_data_structures_iterations == uint64_t(kBenchmarkSize));
    //  Collect throughput for the benchmark.
    state.SetItemsProcessed(kBenchmarkSize);
    // Destroy the skeleton now, recreate on next run.
    // If we are a delete benchmark, ensure we deleted some stuff
    if (skel_->bss->bench_data_structures_deletes)
      std::cerr << "kBenchmarSize=" << kBenchmarkSize << ", deletes=" << skel_->bss->bench_data_structures_deletes
                << '\n';
    skel_.Destroy();
  }

  void PopulateDataStructure(benchmark::State& state, struct bpf_program *prog) {
    // Populate the data structure from one thread only.
    //
    // Note that threads will continue executing and form a barrier at start of
    // benchmarking loop until we return from this function.
    if (state.thread_index() != 0) {
      return;
    }

    // We use this naming scheme for update, lookup, delete style benchmarks to
    // be able to figure out if we need to pre-populate a given data structure.
    if (!state.name().ends_with("_lookup") && !state.name().ends_with("_delete")) {
      return;
    }

    // Depending on the distribution type, choose the right one.
    const auto& dist_ = D == Uniform ? U_dist_ : Z_dist_;
    // If we are a lookup or delete benchmark, let's run the update program
    // repeatedly to fill the data structure. Note that this will update per-CPU
    // state that is typically measured during a benchmark as well.
    for (auto it : dist_) {
      // Run update benchmark on current skeleton
      auto vec = CreateKeyValueBuffer(state, it, state.range(0), state.range(1));

      int ret = RunProg(state, prog, static_cast<void *>(vec.data()), state.range(0) + state.range(1),
                        static_cast<void *>(vec.data()), state.range(0) + state.range(1));
      if (ret < 0) {
        return;
      }
      uint64_t iter_duration = vec[0];
      // Not necessary, but nice to be sure this stuff is working correctly even
      // here.
      assert(iter_duration != 0);
    }
    // Reset counter
    skel_->bss->bench_data_structures_iterations = 0;
  }

  bpf::Skeleton<T> skel_;
};

void RunBenchmark(benchmark::State& state, struct bpf_program *prog, uint64_t dist_key) {
  auto vec = CreateKeyValueBuffer(state, dist_key, state.range(0), state.range(1));

  int ret = RunProg(state, prog, static_cast<void *>(vec.data()), state.range(0) + state.range(1),
                    static_cast<void *>(vec.data()), state.range(0) + state.range(1), true);
  if (ret < 0) {
    return;
  }
  uint64_t iter_duration = vec[0];
  assert(iter_duration);
  state.SetIterationTime(iter_duration * 1e-9);
}

void ConfigHashmap(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel, ConfigState cstate) {
  switch (cstate) {
    case kAfterOpen:
    case kAfterLoad:
      break;
    default:
      state.SkipWithError("Unhandled cstate, please update");
  }

  if (cstate != kAfterOpen) {
    return;
  }

  struct bpf_map *map = skel->maps.bench_hashmap_prealloc;

  int ret = bpf_map__set_key_size(map, state.range(0));
  if (ret < 0) {
    state.SkipWithError("Failed to set key size for map");
    return;
  }

  ret = bpf_map__set_value_size(map, state.range(1));
  if (ret < 0) {
    state.SkipWithError("Failed to set value size for map");
    return;
  }

  ret = bpf_map__set_max_entries(map, kBenchmarkSize);
  if (ret < 0) {
    state.SkipWithError("Failed to set max entries for map");
    return;
  }
}

uint64_t next_pow2(uint64_t x) {
  uint64_t p = 1;
  while (p < x) p *= 2;
  return p;
}

void ConfigHashmapFFKX(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel, enum ConfigState cstate) {
  switch (cstate) {
    case kAfterOpen:
    case kAfterLoad:
      break;
    default:
      state.SkipWithError("Unhandled cstate, please update");
  }

  // Resize lock array size
  if (cstate == kAfterOpen) {
    // Resize hashmap lock buckets
    int ret = bpf_map__set_max_entries(skel->maps.ffkx_hashmap_lock_map, next_pow2(kBenchmarkSize));
    if (ret) {
      state.SkipWithError("Failed to resize FFKX hashmap lock array");
      return;
    }
  }

  if (cstate != kAfterLoad) {
    return;
  }

  // Create a heap allocator for the FFKX heap
  absl::StatusOr<bpf::HeapAllocator> ma = absl::InternalError("Placeholder heap status");
  if (skel->rodata->bench_data_structures_multithreaded) {
    // Prepopulate per-CPU pools, and then populate global heap with as many
    // elements.
    ma = CreateDefaultHeap(skel, kBenchmarkIterations);
  } else {
    // FIXME: We use this for eval, but maybe we should stick to GlobalHeap to
    // simulate a atomic cmpxchg operation?
    ma = CreateGlobalHeap(skel, kBenchmarkIterations);
  }
  if (!ma.ok()) {
    std::cout << ma.status() << std::endl;
    assert(!ma.status().ToString().data());
  }

  // We need to allocate map memory + NR_CPUS * ffkx_hashmap_elem
  const int cpus = libbpf_num_possible_cpus();
  assert(cpus > 0);
  skel->bss->bench_hashmap_ffkx =
      ma->Allocate<struct ffkx_hashmap>(offsetof(struct ffkx_hashmap, pcpu_elem_queue[cpus])).value();
  assert(kBenchmarkSize <= 1'000'000);
  skel->bss->bench_ffkx_hashmap_buckets =
      ma->Allocate<struct ffkx_hashmap_bucket>(next_pow2(kBenchmarkSize) * sizeof(struct ffkx_hashmap_bucket)).value();
  skel->bss->bench_ffkx_hashmap_nr_buckets = next_pow2(kBenchmarkSize);

  char buf[16];
  int ret = RunProg(state, skel->progs.bench_ffkx_hashmap_init, static_cast<void *>(buf), sizeof(buf), nullptr, 0);
  if (ret < 0) {
    return;
  }
}

void ConfigLinkedListCommon(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel,
                            enum ConfigState cstate) {
  switch (cstate) {
    case kAfterOpen:
    case kAfterLoad:
      break;
    default:
      state.SkipWithError("Unhandled cstate, please update");
      return;
  }

  if (cstate != kAfterLoad) {
    return;
  }

  // Create a heap allocator for the FFKX heap
  absl::StatusOr<bpf::HeapAllocator> ma = absl::InternalError("Placeholder heap status");
  if (state.threads() > 1) {
    // Prepopulate per-CPU pools, and then populate global heap with as many
    // elements.
    ma = CreateDefaultHeap(skel, kBenchmarkIterations);
  } else {
    ma = CreateOneCPUHeap(skel, kBenchmarkIterations);
  }
  if (!ma.ok()) {
    std::cout << ma.status() << std::endl;
    assert(!ma.status().ToString().data());
    return;
  }

  char buf[16];
  int ret = RunProg(state, skel->progs.bench_linked_list_init, static_cast<void *>(buf), sizeof(buf), nullptr, 0);
  if (ret < 0) {
    return;
  }
}

void ConfigLinkedList(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel, enum ConfigState cstate) {
  ConfigLinkedListCommon(state, skel, cstate);
}

void ConfigLinkedListFFKX(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel,
                          enum ConfigState cstate) {
  // List initialization needs to be different, so set to true.
  skel->bss->bench_linked_list_ffkx_mode = true;
  return ConfigLinkedListCommon(state, skel, cstate);
}

void ConfigRBTree(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel, enum ConfigState cstate) {
  if (cstate != kAfterLoad) {
    return;
  }
  // Create a heap allocator for the FFKX heap
  absl::StatusOr<bpf::HeapAllocator> ma = absl::InternalError("Placeholder heap status");
  if (state.threads() > 1) {
    // Prepopulate per-CPU pools, and then populate global heap with as many
    // elements.
    ma = CreateDefaultHeap(skel, kBenchmarkIterations);
  } else {
    ma = CreateOneCPUHeap(skel, kBenchmarkIterations);
  }
  if (!ma.ok()) {
    std::cout << ma.status() << std::endl;
    assert(!ma.status().ToString().data());
    return;
  }

  // FIXME: Use ffkx_rb_root_cached
  skel->bss->ffkx_rb_root = reinterpret_cast<struct ffkx_rb_root_cached *>(
      ma->Allocate<struct rb_root_cached>(sizeof(struct rb_root_cached)).value());
  char buf[16];
  int ret = RunProg(state, skel->progs.bench_rbtree_init, static_cast<void *>(buf), sizeof(buf), nullptr, 0);
  if (ret < 0) {
    return;
  }
}

void ConfigSkiplist(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel, enum ConfigState cstate) {
  if (cstate != kAfterLoad) {
    return;
  }
  // Create a heap allocator for the FFKX heap
  absl::StatusOr<bpf::HeapAllocator> ma = absl::InternalError("Placeholder heap status");
  if (state.threads() > 1) {
    // Prepopulate per-CPU pools, and then populate global heap with as many
    // elements.
    ma = CreateDefaultHeap(skel, kBenchmarkIterations);
  } else {
    ma = CreateDefaultHeap(skel, kBenchmarkIterations);
  }
  if (!ma.ok()) {
    std::cout << ma.status() << std::endl;
    assert(!ma.status().ToString().data());
    return;
  }

  // FIXME:Use ffkx_rb_root_cached
  skel->bss->ffkx_skiplist_head = ma->Allocate<struct ffkx_skiplist_elem>().value();
  memset(skel->bss->ffkx_skiplist_head, 0, sizeof(struct ffkx_skiplist_elem));  // FIXME
  skel->bss->ffkx_skiplist_prev =
      ma->Allocate<struct ffkx_skiplist_elem *>(sizeof(*skel->bss->ffkx_skiplist_prev) * MAX_SKIPLIST_HEIGHT).value();
  char buf[16];
  int ret = RunProg(state, skel->progs.bench_skiplist_init, static_cast<void *>(buf), sizeof(buf), nullptr, 0);
  if (ret < 0) {
    return;
  }
}

void ConfigSketch(benchmark::State& state, bpf::Skeleton<bench_data_structures>& skel, enum ConfigState cstate) {
  if (cstate != kAfterLoad) {
    return;
  }
  // Create a heap allocator for the FFKX heap
  absl::StatusOr<bpf::HeapAllocator> ma = absl::InternalError("Placeholder heap status");
  if (state.threads() > 1) {
    // Prepopulate per-CPU pools, and then populate global heap with as many
    // elements.
    // FIXME: Hardcoded since we don't need memory
    ma = CreateDefaultHeap(skel, 4);  // kBenchmarkIterations);
  } else {
    // FIXME: Hardcoded since we don't need memory
    ma = CreateOneCPUHeap(skel, 4);  // kBenchmarkIterations);
  }
  if (!ma.ok()) {
    std::cout << ma.status() << std::endl;
    assert(!ma.status().ToString().data());
    return;
  }

  // countsketch
  skel->bss->ffkx_countsketch = ma->Allocate<struct countsketch>().value();
  memset(skel->bss->ffkx_countsketch, 0, sizeof(*skel->bss->ffkx_countsketch));
  // countminsketc
  skel->bss->ffkx_countminsketch = ma->Allocate<struct countmin>().value();
  memset(skel->bss->ffkx_countminsketch, 0, sizeof(*skel->bss->ffkx_countminsketch));
  char buf[16];
  int ret = RunProg(state, skel->progs.bench_sketch_init, static_cast<void *>(buf), sizeof(buf), nullptr, 0);
  if (ret < 0) {
    return;
  }
}
/*
void ConfigNop(benchmark::State&, bpf::Skeleton<bench_data_structures>&, enum ConfigState) {
	return;
}
*/
}  // namespace

#define __FFKX_BENCHMARK_DEFINE_DS(distrib, tag, id, name, sfx, config, threads, transparent)           \
  BENCHMARK_TEMPLATE_DEFINE_F(SkeletonFixture, tag##_##id##_##name##_##sfx##_##threads##_##transparent, \
                              bench_data_structures, config, distrib, transparent)                      \
  (benchmark::State & state) {                                                                          \
    PopulateDataStructure(state, skel_->progs.bench##_##name##_##update);                               \
    auto it = tag##_##dist_.begin();                                                                    \
    for (auto _ : state) {                                                                              \
      RunBenchmark(state, skel_->progs.bench##_##name##_##sfx, *it);                                    \
      ++it;                                                                                             \
      if (it == tag##_##dist_.end()) {                                                                  \
        it = tag##_##dist_.begin();                                                                     \
      }                                                                                                 \
    }                                                                                                   \
  }

#define __FFKX_BENCHMARK_DEFINE(distrib, tag, id, name, config, threads, transparent)                                  \
  BENCHMARK_TEMPLATE_DEFINE_F(SkeletonFixture, tag##_##id##_##name##_##threads##_##transparent, bench_data_structures, \
                              config, distrib, transparent)                                                            \
  (benchmark::State & state) {                                                                                         \
    auto it = tag##_##dist_.begin();                                                                                   \
    for (auto _ : state) {                                                                                             \
      RunBenchmark(state, skel_->progs.bench##_##name, *it);                                                           \
      ++it;                                                                                                            \
      if (it == tag##_##dist_.end()) {                                                                                 \
        it = tag##_##dist_.begin();                                                                                    \
      }                                                                                                                \
    }                                                                                                                  \
  }

#define __FFKX_BENCHMARK_REGISTER_DS(distrib, tag, id, name, sfx, config, keysz, valsz, threads, transparent) \
  BENCHMARK_REGISTER_F(SkeletonFixture, tag##_##id##_##name##_##sfx##_##threads##_##transparent)              \
      ->Name(#distrib "/" #name "_" #sfx)                                                                     \
      ->ArgNames({"key", "val", "items", "trans"})                                                            \
      ->Args({keysz, valsz, kBenchmarkSize, transparent})                                                     \
      ->Iterations(kBenchmarkIterations)                                                                      \
      ->UseManualTime()                                                                                       \
      ->Threads(threads);

#define __FFKX_BENCHMARK_REGISTER(distrib, tag, id, name, config, keysz, valsz, threads, transparent) \
  BENCHMARK_REGISTER_F(SkeletonFixture, tag##_##id##_##name##_##threads##_##transparent)              \
      ->Name(#distrib "/" #name)                                                                      \
      ->ArgNames({"key", "val", "items", "trans"})                                                    \
      ->Args({keysz, valsz, kBenchmarkSize, transparent})                                             \
      ->Iterations(kBenchmarkIterations)                                                              \
      ->UseManualTime()                                                                               \
      ->Threads(threads);

#define __FFKX_BENCHMARK_DS(distrib, tag, id, name, sfx, config, keysz, valsz, threads, transparent) \
  __FFKX_BENCHMARK_DEFINE_DS(distrib, tag, id, name, sfx, config, threads, transparent);             \
  __FFKX_BENCHMARK_REGISTER_DS(distrib, tag, id, name, sfx, config, keysz, valsz, threads, transparent);

#define __FFKX_BENCHMARK(distrib, tag, id, name, sfx, config, keysz, valsz, threads, transparent) \
  __FFKX_BENCHMARK_DEFINE(distrib, tag, id, name, config, threads, transparent);                  \
  __FFKX_BENCHMARK_REGISTER(distrib, tag, id, name, config, keysz, valsz, threads, transparent);

#define _FFKX_BENCHMARK_DS(distrib, tag, name, sfx, config, threads, transparent)        \
  __FFKX_BENCHMARK_DS(distrib, tag, 1, name, sfx, config, 32, 64, threads, transparent);
//  __FFKX_BENCHMARK_DS(distrib, tag, 2, name, sfx, config, 64, 128, threads, transparent);

/*                                                                                           \
  __FFKX_BENCHMARK_DS(distrib, tag, 1, name, sfx, config, 8, 16, threads, transparent);      \
  __FFKX_BENCHMARK_DS(distrib, tag, 2, name, sfx, config, 16, 32, threads, transparent);     \
  __FFKX_BENCHMARK_DS(distrib, tag, 3, name, sfx, config, 32, 64, threads, transparent);     \
  __FFKX_BENCHMARK_DS(distrib, tag, 4, name, sfx, config, 64, 128, threads, transparent);    \
  __FFKX_BENCHMARK_DS(distrib, tag, 5, name, sfx, config, 128, 256, threads, transparent);   \
  __FFKX_BENCHMARK_DS(distrib, tag, 6, name, sfx, config, 256, 512, threads, transparent);   \
  __FFKX_BENCHMARK_DS(distrib, tag, 7, name, sfx, config, 512, 1024, threads, transparent);  \
  __FFKX_BENCHMARK_DS(distrib, tag, 8, name, sfx, config, 1024, 2048, threads, transparent); \
*/
#define _FFKX_BENCHMARK(distrib, tag, name, sfx, config, threads, transparent)        \
  __FFKX_BENCHMARK(distrib, tag, 1, name, sfx, config, 32, 64, threads, transparent);
//  __FFKX_BENCHMARK(distrib, tag, 2, name, sfx, config, 64, 128, threads, transparent);

/*
  __FFKX_BENCHMARK(distrib, tag, 1, name, sfx, config, 8, 16, threads, transparent);     \
  __FFKX_BENCHMARK(distrib, tag, 2, name, sfx, config, 16, 32, threads, transparent);    \
  __FFKX_BENCHMARK(distrib, tag, 3, name, sfx, config, 32, 64, threads, transparent);    \
  __FFKX_BENCHMARK(distrib, tag, 4, name, sfx, config, 64, 128, threads, transparent);   \
  __FFKX_BENCHMARK(distrib, tag, 5, name, sfx, config, 128, 256, threads, transparent);  \
  __FFKX_BENCHMARK(distrib, tag, 6, name, sfx, config, 256, 512, threads, transparent);  \
  __FFKX_BENCHMARK(distrib, tag, 7, name, sfx, config, 512, 1024, threads, transparent); \
  __FFKX_BENCHMARK(distrib, tag, 8, name, sfx, config, 1024, 2048, threads, transparent);
*/
#define FFKX_BENCHMARK_DS(name, config, threads, transparent)                 \
  _FFKX_BENCHMARK_DS(Uniform, U, name, update, config, threads, transparent); \
  _FFKX_BENCHMARK_DS(Uniform, U, name, lookup, config, threads, transparent); \
  _FFKX_BENCHMARK_DS(Uniform, U, name, delete, config, threads, transparent); \
  _FFKX_BENCHMARK_DS(Zipfian, Z, name, update, config, threads, transparent); \
  _FFKX_BENCHMARK_DS(Zipfian, Z, name, lookup, config, threads, transparent); \
  _FFKX_BENCHMARK_DS(Zipfian, Z, name, delete, config, threads, transparent);

#define FFKX_BENCHMARK(name, config, threads, transparent)                \
  _FFKX_BENCHMARK(Uniform, U, name, bench, config, threads, transparent); \
  _FFKX_BENCHMARK(Zipfian, Z, name, bench, config, threads, transparent);

// FIXME: Trans gives EINVAL
// FIXME: Threads gives segfault

// FFKX_BENCHMARK(bpf_nop, ConfigNop, 1, false);

// -- RBTree -- //

FFKX_BENCHMARK_DS(bpf_rbtree, ConfigRBTree, 1, false);
FFKX_BENCHMARK_DS(ffkx_rbtree, ConfigRBTree, 1, false);

// -- Hashmap -- //

FFKX_BENCHMARK_DS(bpf_hashmap, ConfigHashmap, 1, false);
FFKX_BENCHMARK_DS(ffkx_hashmap, ConfigHashmapFFKX, 1, false);

// -- Linked List -- //

FFKX_BENCHMARK_DS(bpf_linked_list, ConfigLinkedList, 1, false);
FFKX_BENCHMARK_DS(bpf_graph_linked_list, ConfigLinkedList, 1, false);
FFKX_BENCHMARK_DS(ffkx_linked_list, ConfigLinkedListFFKX, 1, false);

// -- Skiplist -- //

FFKX_BENCHMARK_DS(bpf_skiplist, ConfigSkiplist, 1, false);
FFKX_BENCHMARK_DS(ffkx_skiplist, ConfigSkiplist, 1, false);

// -- Sketch -- //

FFKX_BENCHMARK(bpf_countsketch, ConfigSketch, 1, false);
FFKX_BENCHMARK(bpf_countminsketch, ConfigSketch, 1, false);
FFKX_BENCHMARK(ffkx_countsketch, ConfigSketch, 1, false);
FFKX_BENCHMARK(ffkx_countminsketch, ConfigSketch, 1, false);
