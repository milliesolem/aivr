// Minimal stub of arrow/memory_pool.h — a concrete MemoryPool and the
// default_memory_pool() accessor. The pool is only a tag in the exercised path;
// the real allocation behaviour is reproduced in buffer.h.
#pragma once

namespace arrow {

class MemoryPool {
 public:
  virtual ~MemoryPool() = default;
};

inline MemoryPool* default_memory_pool() {
  static MemoryPool pool;
  return &pool;
}

}  // namespace arrow
