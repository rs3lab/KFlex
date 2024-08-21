// SPDX-License-Identifier: MIT
#ifndef FFKX_BENCH_RANDOM_UTIL_HPP
#define FFKX_BENCH_RANDOM_UTIL_HPP

#include <absl/random/random.h>
#include <absl/random/uniform_int_distribution.h>
#include <absl/random/zipf_distribution.h>

#include <map>
#include <vector>

namespace ffkx {
namespace bench {

inline std::vector<uint64_t> GenerateUniformRandomDistribution(size_t size) {
  std::vector<uint64_t> vec;
  absl::BitGen bitgen;

  vec.reserve(size);
  std::generate_n(std::back_inserter(vec), size,
                  [&] { return absl::Uniform<uint64_t>(absl::IntervalClosed, bitgen, 0, size); });
  return vec;
}

inline std::vector<uint64_t> GenerateZipfianSkewedDistribution(size_t size, double q = 1.00001, double v = 0.99999) {
  std::vector<uint64_t> vec;
  absl::BitGen bitgen;

  vec.reserve(size);
  std::generate_n(std::back_inserter(vec), size, [&] { return absl::Zipf<uint64_t>(bitgen, size, q, v); });
  return vec;
}

inline std::map<double, size_t> GenerateZipfianFrequencyMap(const std::vector<uint64_t>& vec) {
  std::map<double, size_t> map;
  for (auto i : vec) {
    map[i]++;
  }
  return map;
}

}  // namespace bench
}  // namespace ffkx

#endif
