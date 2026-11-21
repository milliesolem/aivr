// Minimal stub of arrow/result.h — a value-or-Status wrapper with the
// ok()/status()/ValueOrDie() surface used by ARROW_ASSIGN_OR_RAISE in the real
// buffer_builder.h.
#pragma once

#include <memory>
#include <utility>

#include "arrow/status.h"

namespace arrow {

template <typename T>
class Result {
 public:
  Result(T value) : status_(Status::OK()), value_(std::move(value)) {}
  Result(Status status) : status_(status), value_() {}
  Result(Result&& other) noexcept
      : status_(other.status_), value_(std::move(other.value_)) {}

  bool ok() const { return status_.ok(); }
  const Status& status() const { return status_; }

  T ValueOrDie() && { return std::move(value_); }
  T& ValueOrDie() & { return value_; }

 private:
  Status status_;
  T value_;
};

}  // namespace arrow
