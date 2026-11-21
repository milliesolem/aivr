// Minimal stub of arrow/util/bit_util.h (plus the arrow::util and
// arrow::internal helpers the real buffer_builder.h references). These
// provide faithful single-scalar equivalents of Arrow's bit utilities; they
// are only needed by the TypedBufferBuilder<bool> specialization, which the
// PoC does not instantiate, but defining them keeps the unmodified header
// fully compilable.
#pragma once

#include <cstdint>
#include <type_traits>

namespace arrow {

namespace bit_util {

inline int64_t BytesForBits(int64_t bits) { return (bits + 7) / 8; }
inline bool IsMultipleOf64(int64_t v) { return (v & 63) == 0; }
inline int64_t RoundUpToMultipleOf64(int64_t v) { return (v + 63) & ~int64_t{63}; }

inline void SetBitTo(uint8_t* bitmap, int64_t i, bool value) {
  if (value) {
    bitmap[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
  } else {
    bitmap[i / 8] &= static_cast<uint8_t>(~(1u << (i % 8)));
  }
}

inline void SetBitsTo(uint8_t* bitmap, int64_t start, int64_t len, bool value) {
  for (int64_t i = 0; i < len; ++i) {
    SetBitTo(bitmap, start + i, value);
  }
}

}  // namespace bit_util

namespace util {

template <typename T>
T* MakeNonNull() {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(1));
}

}  // namespace util

namespace internal {

template <typename Generator>
inline void GenerateBitsUnrolled(uint8_t* bitmap, int64_t start_offset,
                                 int64_t num_bits, Generator&& gen) {
  for (int64_t i = 0; i < num_bits; ++i) {
    bit_util::SetBitTo(bitmap, start_offset + i, gen());
  }
}

inline void CopyBitmap(const uint8_t* src, int64_t src_offset, int64_t num_bits,
                       uint8_t* dst, int64_t dst_offset) {
  for (int64_t i = 0; i < num_bits; ++i) {
    bool b = (src[(src_offset + i) / 8] >> ((src_offset + i) % 8)) & 1;
    bit_util::SetBitTo(dst, dst_offset + i, b);
  }
}

inline int64_t CountSetBits(const uint8_t* bitmap, int64_t offset, int64_t num_bits) {
  int64_t count = 0;
  for (int64_t i = 0; i < num_bits; ++i) {
    if ((bitmap[(offset + i) / 8] >> ((offset + i) % 8)) & 1) {
      ++count;
    }
  }
  return count;
}

}  // namespace internal

}  // namespace arrow
