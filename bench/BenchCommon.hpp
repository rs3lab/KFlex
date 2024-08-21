// SPDX-License-Identifier: MIT
#ifndef FFKX_BENCH_COMMON_HPP
#define FFKX_BENCH_COMMON_HPP

#include <cstdint>
#include <vector>

namespace ffkx {
namespace bench {

inline std::vector<uint64_t> uniform_dist_500K;
inline std::vector<uint64_t> uniform_dist_1M;
inline std::vector<uint64_t> zipf_dist_sk99_500K;
inline std::vector<uint64_t> zipf_dist_sk99_1M;

}  // namespace bench
}  // namespace ffkx

#endif
