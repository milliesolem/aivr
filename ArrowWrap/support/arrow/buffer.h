// Minimal stub of arrow/buffer.h — Buffer / ResizableBuffer / PoolBuffer plus
// the AllocateBuffer / AllocateResizableBuffer free functions. PoolBuffer
// reproduces Arrow's malloc-backed resizable buffer (capacity rounded up to a
// 64-byte multiple) so the BufferBuilder's normal allocation path is faithful.
// The vulnerable integer-overflow arithmetic lives entirely in the unmodified
// real buffer_builder.h, NOT here.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string_view>

#include "arrow/memory_pool.h"
#include "arrow/result.h"
#include "arrow/status.h"

namespace arrow {

constexpr int64_t kDefaultBufferAlignment = 64;

class Buffer {
 public:
  virtual ~Buffer() = default;
  const uint8_t* data() const { return data_; }
  uint8_t* mutable_data() { return data_; }
  int64_t size() const { return size_; }
  int64_t capacity() const { return capacity_; }

 protected:
  uint8_t* data_ = nullptr;
  int64_t size_ = 0;
  int64_t capacity_ = 0;
};

class ResizableBuffer : public Buffer {
 public:
  virtual Status Resize(int64_t new_size, bool shrink_to_fit = true) = 0;
  virtual Status Reserve(int64_t new_capacity) = 0;

  void ZeroPadding() {
    if (size_ < capacity_) {
      std::memset(data_ + size_, 0, static_cast<size_t>(capacity_ - size_));
    }
  }
};

class PoolBuffer : public ResizableBuffer {
 public:
  ~PoolBuffer() override { std::free(data_); }

  Status Resize(int64_t new_size, bool shrink_to_fit = true) override {
    if (new_size < 0) {
      return Status::Invalid("Negative buffer resize: ", new_size);
    }
    const int64_t rounded = (new_size + 63) & ~int64_t{63};
    if (rounded > capacity_) {
      uint8_t* p = static_cast<uint8_t*>(std::realloc(data_, rounded));
      if (!p) {
        return Status::OutOfMemory("realloc failed");
      }
      data_ = p;
      capacity_ = rounded;
    }
    size_ = new_size;
    return Status::OK();
  }

  Status Reserve(int64_t new_capacity) override {
    return Resize(new_capacity, false);
  }
};

inline Result<std::shared_ptr<ResizableBuffer>> AllocateResizableBuffer(
    int64_t size, int64_t alignment = kDefaultBufferAlignment,
    MemoryPool* pool = nullptr) {
  std::shared_ptr<ResizableBuffer> buf = std::make_shared<PoolBuffer>();
  Status st = buf->Resize(size, false);
  if (!st.ok()) {
    return st;
  }
  return buf;
}

inline Result<std::shared_ptr<Buffer>> AllocateBuffer(
    int64_t size, int64_t alignment = kDefaultBufferAlignment,
    MemoryPool* pool = nullptr) {
  auto poolbuf = std::make_shared<PoolBuffer>();
  Status st = poolbuf->Resize(size, false);
  if (!st.ok()) {
    return st;
  }
  std::shared_ptr<Buffer> buf = poolbuf;
  return buf;
}

}  // namespace arrow
