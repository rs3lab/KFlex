// SPDX-License-Identifier: MIT
#include <absl/flags/config.h>
#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/flags/usage_config.h>
#include <absl/random/internal/distribution_test_util.h>
#include <absl/random/random.h>
#include <absl/random/zipf_distribution.h>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_format.h>
#include <absl/strings/str_split.h>
#include <absl/strings/string_view.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include <thread>
// clang-format off
// FIXME: Use the same definitions in the kernel somehow, switch to a kernel
// module.
#define MAX_SKIPLIST_HEIGHT 32

struct ffkx_skiplist_elem {
  uint32_t height;
  uint32_t key_size;
  uint32_t value_size;
  struct ffkx_skiplist_elem *next[MAX_SKIPLIST_HEIGHT];
  char buf[];
};
//clang-format on

#include <BPF.hpp>
#include <BPFHeapAllocator.hpp>
// clang-format off <order after heap allocator ffkx_malloc.h>
#include <ffkx_hashmap.h>
#include <ffkx_malloc.h>
#include <ffkx_memcached.skel.h>
#include <ffkx_memcache.skel.h>
#include <ffkx_redis.skel.h>
// clang-format on
#include <File.hpp>
#include <Socket.hpp>
#include <iostream>

ABSL_FLAG(bool, kmemcached, false, "In-kernel memcached mode");
ABSL_FLAG(bool, kmemcache, false, "In-kernel memcache mode");
ABSL_FLAG(bool, cod, false, "In-kernel memcache mode cod");
ABSL_FLAG(int, ifindex, false, "In-kernel memcache mode ifindex");
ABSL_FLAG(bool, kredis, false, "In-kernel Redis mode");

int zipf_main(double q, double v) {
  std::vector<double> vec;
  absl::BitGen gen;
  std::map<double, int> freq;

  size_t size = 10000;
  std::generate_n(std::back_inserter(vec), size, [&] { return absl::Zipf<size_t>(gen, size, q, v); });

  const auto moments = absl::random_internal::ComputeDistributionMoments(vec);
  for (auto i : vec) {
    freq[i] += 1;
  }

  for (auto it = freq.rbegin(); it != freq.rend(); ++it) {
    const auto p = *it;
    std::cout << "item=" << p.first << ", freq=" << p.second << std::endl;
  }
  std::cout << "skewness=" << moments.skewness << std::endl;
  std::cout << "size=" << freq.size() << std::endl;
  return 0;
}

constexpr int kRedisHeapCapacity = 10'000'000;
constexpr int kRedisMapSize = 1'000'000;

namespace {

uint64_t next_pow2(uint64_t x) {
  uint64_t p = 1;
  while (p < x) p *= 2;
  return p;
}

}  // namespace

absl::Status RedisInitSkel(ffkx::bpf::Skeleton<ffkx_redis>& skel) {
  // FIXME: This is needed for concurrent map, and needs to be done before
  // lload, but here we don't need it, also disabled in kernel.
  /*
int ret = bpf_map__set_max_entries(skel->maps.ffkx_hashmap_lock_map, next_pow2(kRedisMapSize));
if (ret < 0) {
return absl::ErrnoToStatus(errno, "Failed to resize lock map");
}
  */

  auto ma = ffkx::bpf::CreateDefaultHeap(skel, kRedisHeapCapacity, 6);
  if (!ma.ok()) {
    return ma.status();
  }

  // We need to allocate map memory + NR_CPUS * ffkx_hashmap_elem
  const int cpus = libbpf_num_possible_cpus();
  assert(cpus > 0);
  skel->bss->ffkx_redis_hashmap =
      ma->Allocate<struct ffkx_hashmap>(offsetof(struct ffkx_hashmap, pcpu_elem_queue[cpus])).value();
  skel->bss->ffkx_redis_hashmap_buckets =
      ma->Allocate<struct ffkx_hashmap_bucket>(next_pow2(kRedisMapSize) * sizeof(struct ffkx_hashmap_bucket)).value();
  skel->bss->ffkx_redis_hashmap_nr_buckets = next_pow2(kRedisMapSize);
  // FIXME: Fix and use constructors.
  skel->bss->ffkx_skiplist_prev =
      ma->Allocate<struct ffkx_skiplist_elem *>(sizeof(*skel->bss->ffkx_skiplist_prev) * MAX_SKIPLIST_HEIGHT).value();

  // FIXME: Do properly with KEY_BUF_SZ
  skel->bss->ffkx_redis_key_buf = ma->Allocate<void>(512 * libbpf_num_possible_cpus()).value();
  skel->bss->ffkx_redis_value_buf = ma->Allocate<void>(512 * libbpf_num_possible_cpus()).value();

  // FIXME: KEY_BUF_SZ macro must be updated in sync
  skel->bss->ffkx_redis_hashmap_key_size = 512;
  // Value is pointer to skiplist
  skel->bss->ffkx_redis_hashmap_value_size = 8;
  skel->bss->ffkx_redis_hashmap_max_entries_size = kRedisMapSize;

  struct bpf_test_run_opts opts;
  INIT_LIBBPF_OPTS(opts);

  char buf[16];
  opts.data_in = static_cast<void *>(buf);
  opts.data_size_in = sizeof(buf);
  opts.data_out = nullptr;
  opts.data_size_out = 0;
  opts.repeat = 1;

  // FIXME: Not need for redis, Always ensure we do CPU 0 for single threaded bench
  if (0) {
    opts.flags = BPF_F_TEST_RUN_ON_CPU;
    opts.cpu = 0;
  }

  int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.ffkx_redis_hashmap_init), &opts);
  if (ret || opts.retval) {
    std::cerr << absl::StrFormat("Failed to run prog %s: ret=%d retval=%d",
                                 bpf_program__name(skel->progs.ffkx_redis_hashmap_init), ret, opts.retval)
              << '\n';
    return absl::ErrnoToStatus(EINVAL, "Init failure");
  }
  return absl::OkStatus();
}

absl::Status RedisAttach(ffkx::bpf::Skeleton<ffkx_redis>& skel) {
  int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
  if (cgroup_fd < 0) {
    return absl::ErrnoToStatus(errno, "Failed to open cgroup root directory.");
  }
  ffkx::io::FileDescriptor fd(cgroup_fd);

  int err = bpf_prog_attach(bpf_program__fd(skel->progs.ffkx_redis_rx_stream_parser), bpf_map__fd(skel->maps.sockhash),
                            BPF_SK_SKB_STREAM_PARSER, 0);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach parser program to sockhash map.");
  }

  err = bpf_prog_attach(bpf_program__fd(skel->progs.ffkx_redis_rx_stream_verdict), bpf_map__fd(skel->maps.sockhash),
                        BPF_SK_SKB_STREAM_VERDICT, 0);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach verdict program to sockhash map.");
  }

  skel->links.ffkx_redis_sockops = bpf_program__attach_cgroup(skel->progs.ffkx_redis_sockops, fd.GetRawFd());
  if (!skel->links.ffkx_redis_sockops) {
    return absl::ErrnoToStatus(errno, "Failed to attach sockops program to root cgroup.");
  }
  return absl::OkStatus();
}

int RedisMain(void) {
  ffkx::bpf::Skeleton<ffkx_redis> skel;

  auto status = skel.Open();
  if (!status.ok()) {
    return 1;
  }

  // Config

  status = skel.Load();
  if (!status.ok()) {
    return 1;
  }

  // FIXME: Investigate that we hang if forgot to init
  auto result = RedisInitSkel(skel);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  result = RedisAttach(skel);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  auto sock = ffkx::net::Socket::MakeTCP();
  if (!sock.ok()) {
    std::cerr << sock.status() << '\n';
    return 1;
  }

  result = sock->BindAny(6969);
  if (!result.ok()) {
    std::cerr << result << '\n';
    return 1;
  }

  result = sock->SetListen(4096);
  if (!result.ok()) {
    std::cerr << result << '\n';
    return 1;
  }

  std::cerr << "ToyRedis ready!\n";
  while (true) {
    auto client = sock->AcceptConnection();
    if (!client.ok()) {
      std::cerr << client.status() << '\n';
      return 1;
    }

    std::cerr << "Accepted a connection, adding socket to sockmap...\n";
    // Persist connection in sockmap
    auto client_fd = std::move(client).value();
    (void)client_fd.Release();
  }
}

//////// Memcached

constexpr int kMemcachedHeapCapacity = 10'000'000;
constexpr int kMemcachedMapSize = 1'000'000;

absl::Status MemcachedInitSkel(ffkx::bpf::Skeleton<ffkx_memcached>& skel, bool before_load) {
  // FIXME: This is needed for concurrent map, and needs to be done before load.
  if (before_load) {
    int ret = bpf_map__set_max_entries(skel->maps.ffkx_hashmap_lock_map, next_pow2(kMemcachedMapSize));
    if (ret < 0) {
      return absl::ErrnoToStatus(errno, "Failed to resize lock map");
    }
    return absl::OkStatus();
  }

  auto ma = ffkx::bpf::CreateDefaultHeap(skel, kMemcachedHeapCapacity, 6);
  if (!ma.ok()) {
    return ma.status();
  }

  // We need to allocate map memory + NR_CPUS * ffkx_hashmap_elem
  const int cpus = libbpf_num_possible_cpus();
  assert(cpus > 0);
  skel->bss->ffkx_memcached_hashmap =
      ma->Allocate<struct ffkx_hashmap>(offsetof(struct ffkx_hashmap, pcpu_elem_queue[cpus])).value();
  skel->bss->ffkx_memcached_hashmap_buckets =
      ma->Allocate<struct ffkx_hashmap_bucket>(next_pow2(kMemcachedMapSize) * sizeof(struct ffkx_hashmap_bucket))
          .value();
  skel->bss->ffkx_memcached_hashmap_nr_buckets = next_pow2(kMemcachedMapSize);

  // FIXME: Do properly with KEY_BUF_SZ
  skel->bss->ffkx_memcached_key_buf = ma->Allocate<void>(1024 * libbpf_num_possible_cpus()).value();
  skel->bss->ffkx_memcached_value_buf = ma->Allocate<void>(1024 * libbpf_num_possible_cpus()).value();

  // FIXME: KEY_BUF_SZ macro must be updated in sync
  skel->bss->ffkx_memcached_hashmap_key_size = 1024;
  // Value is pointer to skiplist
  skel->bss->ffkx_memcached_hashmap_value_size = 1024;
  skel->bss->ffkx_memcached_hashmap_max_entries_size = kMemcachedMapSize;

  struct bpf_test_run_opts opts;
  INIT_LIBBPF_OPTS(opts);

  char buf[16];
  opts.data_in = static_cast<void *>(buf);
  opts.data_size_in = sizeof(buf);
  opts.data_out = nullptr;
  opts.data_size_out = 0;
  opts.repeat = 1;

  int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.ffkx_memcached_hashmap_init), &opts);
  if (ret || opts.retval) {
    std::cerr << absl::StrFormat("Failed to run prog %s: ret=%d retval=%d",
                                 bpf_program__name(skel->progs.ffkx_memcached_hashmap_init), ret, opts.retval)
              << '\n';
    return absl::ErrnoToStatus(EINVAL, "Init failure");
  }
  return absl::OkStatus();
}

absl::Status MemcachedAttach(ffkx::bpf::Skeleton<ffkx_memcached>& skel) {
  int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
  if (cgroup_fd < 0) {
    return absl::ErrnoToStatus(errno, "Failed to open cgroup root directory.");
  }
  ffkx::io::FileDescriptor fd(cgroup_fd);

  int err = bpf_prog_attach(bpf_program__fd(skel->progs.ffkx_memcached_rx_stream_parser),
                            bpf_map__fd(skel->maps.sockhash), BPF_SK_SKB_STREAM_PARSER, 0);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach parser program to sockhash map.");
  }

  err = bpf_prog_attach(bpf_program__fd(skel->progs.ffkx_memcached_rx_stream_verdict), bpf_map__fd(skel->maps.sockhash),
                        BPF_SK_SKB_STREAM_VERDICT, 0);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach verdict program to sockhash map.");
  }

  skel->links.ffkx_memcached_sockops = bpf_program__attach_cgroup(skel->progs.ffkx_memcached_sockops, fd.GetRawFd());
  if (!skel->links.ffkx_memcached_sockops) {
    return absl::ErrnoToStatus(errno, "Failed to attach sockops program to root cgroup.");
  }
  return absl::OkStatus();
}

int MemcachedMain(void) {
  ffkx::bpf::Skeleton<ffkx_memcached> skel;

  auto status = skel.Open();
  if (!status.ok()) {
    return 1;
  }

  // Config
  auto result = MemcachedInitSkel(skel, true);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  status = skel.Load();
  if (!status.ok()) {
    return 1;
  }

  // FIXME: Investigate that we hang if forgot to init
  result = MemcachedInitSkel(skel, false);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  result = MemcachedAttach(skel);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  auto thr_main = [&] {
    auto sock = ffkx::net::Socket::MakeTCP();
    if (!sock.ok()) {
      std::cerr << sock.status() << '\n';
      return 1;
    }

    result = sock->BindAny(6969);
    if (!result.ok()) {
      std::cerr << result << '\n';
      return 1;
    }

    result = sock->SetListen(4096);
    if (!result.ok()) {
      std::cerr << result << '\n';
      return 1;
    }

    std::cerr << "Memcached ready!\n";
    while (true) {
      auto client = sock->AcceptConnection();
      if (!client.ok()) {
        std::cerr << client.status() << '\n';
        return 1;
      }

      std::cerr << "Accepted a connection, adding socket to sockmap...\n";
      // Persist connection in sockmap
      auto client_fd = std::move(client).value();
      (void)client_fd.Release();
    }
  };

  std::vector<std::thread> thr_vec;
  for (int i = 0; i < 16; i++) thr_vec.push_back(std::thread(thr_main));
  for (auto& t : thr_vec) {
    t.join();
  }
  return 0;
}
////////
///
///
//////// Memcache

constexpr int kMemcacheHeapCapacity = 10'000'000;
constexpr int kMemcacheMapSize = 1'000'000;

absl::Status MemcacheInitSkel(ffkx::bpf::Skeleton<ffkx_memcache>& skel, bool before_load) {
  // FIXME: This is needed for concurrent map, and needs to be done before load.
  if (before_load) {
    int ret = bpf_map__set_max_entries(skel->maps.ffkx_hashmap_lock_map, next_pow2(kMemcacheMapSize));
    if (ret < 0) {
      return absl::ErrnoToStatus(errno, "Failed to resize lock map");
    }
    return absl::OkStatus();
  }

  auto ma = ffkx::bpf::CreateDefaultHeap(skel, kMemcacheHeapCapacity, 6);
  if (!ma.ok()) {
    return ma.status();
  }

  // We need to allocate map memory + NR_CPUS * ffkx_hashmap_elem
  const int cpus = libbpf_num_possible_cpus();
  assert(cpus > 0);
  skel->bss->ffkx_memcache_hashmap =
      ma->Allocate<struct ffkx_hashmap>(offsetof(struct ffkx_hashmap, pcpu_elem_queue[cpus])).value();
  skel->bss->ffkx_memcache_hashmap_buckets =
      ma->Allocate<struct ffkx_hashmap_bucket>(next_pow2(kMemcacheMapSize) * sizeof(struct ffkx_hashmap_bucket))
          .value();
  skel->bss->ffkx_memcache_hashmap_nr_buckets = next_pow2(kMemcacheMapSize);

  // FIXME: Do properly with KEY_BUF_SZ
  skel->bss->ffkx_memcache_key_buf = ma->Allocate<void>(1024 * libbpf_num_possible_cpus()).value();
  skel->bss->ffkx_memcache_value_buf = ma->Allocate<void>(1024 * libbpf_num_possible_cpus()).value();

  // FIXME: KEY_BUF_SZ macro must be updated in sync
  skel->bss->ffkx_memcache_hashmap_key_size = 1024;
  // Value is pointer to skiplist
  skel->bss->ffkx_memcache_hashmap_value_size = 1024;
  skel->bss->ffkx_memcache_hashmap_max_entries_size = kMemcacheMapSize;

  struct bpf_test_run_opts opts;
  INIT_LIBBPF_OPTS(opts);

  char buf[16];
  opts.data_in = static_cast<void *>(buf);
  opts.data_size_in = sizeof(buf);
  opts.data_out = nullptr;
  opts.data_size_out = 0;
  opts.repeat = 1;

  int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.ffkx_memcache_hashmap_init), &opts);
  if (ret || opts.retval) {
    std::cerr << absl::StrFormat("Failed to run prog %s: ret=%d retval=%d",
                                 bpf_program__name(skel->progs.ffkx_memcache_hashmap_init), ret, opts.retval)
              << '\n';
    return absl::ErrnoToStatus(EINVAL, "Init failure");
  }
  return absl::OkStatus();
}

absl::Status MemcacheAttach(ffkx::bpf::Skeleton<ffkx_memcache>& skel) {
  int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
  if (cgroup_fd < 0) {
    return absl::ErrnoToStatus(errno, "Failed to open cgroup root directory.");
  }
  ffkx::io::FileDescriptor fd(cgroup_fd);

  int err = bpf_prog_attach(bpf_program__fd(skel->progs.ffkx_memcache_rx_stream_parser),
                            bpf_map__fd(skel->maps.sockhash), BPF_SK_SKB_STREAM_PARSER, 0);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach parser program to sockhash map.");
  }

  err = bpf_prog_attach(bpf_program__fd(skel->progs.ffkx_memcache_rx_stream_verdict), bpf_map__fd(skel->maps.sockhash),
                        BPF_SK_SKB_STREAM_VERDICT, 0);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach verdict program to sockhash map.");
  }

  skel->links.ffkx_memcache_sockops = bpf_program__attach_cgroup(skel->progs.ffkx_memcache_sockops, fd.GetRawFd());
  if (!skel->links.ffkx_memcache_sockops) {
    return absl::ErrnoToStatus(errno, "Failed to attach sockops program to root cgroup.");
  }

  int ret = bpf_xdp_attach(absl::GetFlag(FLAGS_ifindex), bpf_program__fd(skel->progs.ffkx_memcache_rx_xdp), 0, nullptr);
  if (ret < 0) {
    return absl::ErrnoToStatus(errno, "Failed to attach to interface");
  }
  return absl::OkStatus();
}

#include <sched.h>

int MemcacheMain(void) {
  ffkx::bpf::Skeleton<ffkx_memcache> skel;

  auto status = skel.Open();
  if (!status.ok()) {
    return 1;
  }

  // Config
  auto result = MemcacheInitSkel(skel, true);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  status = skel.Load();
  if (!status.ok()) {
    return 1;
  }

  // FIXME: Investigate that we hang if forgot to init
  result = MemcacheInitSkel(skel, false);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  result = MemcacheAttach(skel);
  if (!result.ok()) {
    std::cerr << result.message() << '\n';
    return 1;
  }

  auto thr_main = [&] {
    auto sock = ffkx::net::Socket::MakeTCP();
    if (!sock.ok()) {
      std::cerr << sock.status() << '\n';
      return 1;
    }

    result = sock->BindAny(6969);
    if (!result.ok()) {
      std::cerr << result << '\n';
      return 1;
    }

    result = sock->SetListen(4096);
    if (!result.ok()) {
      std::cerr << result << '\n';
      return 1;
    }

    if (absl::GetFlag(FLAGS_cod)) {
      std::cerr << "Co-design enable";
      skel->data->codesign_enable = true;
    }
    std::cerr << "Memcache ready!\n";
    while (true) {
      auto client = sock->AcceptConnection();
      if (!client.ok()) {
        std::cerr << client.status() << '\n';
        return 1;
      }

      std::cerr << "Accepted a connection, adding socket to sockmap...\n";
      // Persist connection in sockmap
      auto client_fd = std::move(client).value();
      (void)client_fd.Release();
    }
  };

  auto sleep_thr = [&](auto i) {
    int cpu = 8 + i;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(gettid(), sizeof(set), &set) == -1) {
      std::cerr << "Failed to set affinity\n";
    }

    struct bpf_test_run_opts opts;
    INIT_LIBBPF_OPTS(opts);

    char buf[64];
    opts.data_in = buf;
    opts.data_size_in = sizeof(buf);
    opts.data_out = buf;
    opts.data_size_out = sizeof(buf);
    opts.repeat = 1;
    sleep(2);
    int ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.codesign), &opts);
    if (ret || opts.retval) {
      std::cerr << "Failed to run prog ret=" << ret << " optval=" << opts.retval << '\n';
    }
  };
  (void)sleep_thr;

  std::vector<std::thread> thr_vec;
  for (int i = 0; i < 16; i++) thr_vec.push_back(std::thread(thr_main));

  for (auto& t : thr_vec) {
    t.join();
  }
  return 0;
}

int main(int argc, char *argv[]) {
  /*
std::cout << "Test ZipF parameters (q and v)\n";
double q, v;
std::cin >> q >> v;
zipf_main(q, v);
*/
  absl::SetProgramUsageMessage("\nffkx 0.1\nUse --helpfull for help.\n");
  absl::ParseCommandLine(argc, argv);

  if (geteuid() != 0) {
    std::cerr << "ffkx needs to be run as root.\n";
    std::cerr << absl::ProgramUsageMessage();
    return 1;
  }

  if (absl::GetFlag(FLAGS_kmemcached) && absl::GetFlag(FLAGS_kredis)) {
    std::cerr << "Please choose one of memcached or Redis modes" << std::endl;
    std::cerr << absl::ProgramUsageMessage();
    return 1;
  }

  if (absl::GetFlag(FLAGS_kredis)) {
    return RedisMain();
  } else if (absl::GetFlag(FLAGS_kmemcached)) {
    return MemcachedMain();
  } else if (absl::GetFlag(FLAGS_kmemcache)) {
    return MemcacheMain();
  }
}
