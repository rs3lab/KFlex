// SPDX-License-Identifier: MIT
#ifndef FFKX_UTILITY_HPP
#define FFKX_UTILITY_HPP

#include <concepts>
#include <type_traits>

// FIXME: Doesn't work, instead says infinite recursion (since base calls itself)
#define FFKX_DERIVED_HAS_METHOD(derived, method)                               \
  static_assert(std::is_member_function_pointer_v<decltype(&derived::method)>, \
		"CRTP: Derived class does not implement " #method)

namespace ffkx {
namespace util {

template <std::size_t K, typename T>
  requires std::integral<T>
T RoundUpTo(T num) {
  return (num + K - 1) / K * K;
}

}  // namespace util
}  // namespace ffkx

#endif
