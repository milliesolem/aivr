// Minimal stub of arrow/status.h — reproduces the Status API surface used by
// the real Arrow buffer_builder.h (OK / CapacityError / OutOfMemory / Invalid).
// The message-formatting stream API is simplified: variadic args are accepted
// and discarded. This does not affect the vulnerable arithmetic under test.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace arrow {

class Status {
 public:
  Status() : code_(0), msg_("OK") {}

  static Status OK() { return Status(0, "OK"); }

  template <typename... Args>
  static Status CapacityError(Args&&... /*args*/) {
    return Status(1, "CapacityError");
  }

  template <typename... Args>
  static Status OutOfMemory(Args&&... /*args*/) {
    return Status(2, "OutOfMemory");
  }

  template <typename... Args>
  static Status Invalid(Args&&... /*args*/) {
    return Status(3, "Invalid");
  }

  bool ok() const { return code_ == 0; }
  int code() const { return code_; }
  const std::string& ToString() const { return msg_; }

 private:
  Status(int code, std::string msg) : code_(code), msg_(std::move(msg)) {}
  int code_;
  std::string msg_;
};

}  // namespace arrow
