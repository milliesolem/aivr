// Minimal stub of arrow/util/int_util_overflow.h — the overflow-checked
// helpers the FIXED buffer_builder.h uses (internal::AddWithOverflow /
// internal::MultiplyWithOverflow). These wrap the compiler builtins, matching
// Arrow's real implementation.
#pragma once

#include <cstdint>

namespace arrow {
namespace internal {

static inline bool AddWithOverflow(int64_t x, int64_t y, int64_t* out) {
  return __builtin_add_overflow(x, y, out);
}

static inline bool MultiplyWithOverflow(int64_t x, int64_t y, int64_t* out) {
  return __builtin_mul_overflow(x, y, out);
}

}  // namespace internal
}  // namespace arrow
