// Minimal stub of arrow/util/macros.h — supplies the control-flow macros the
// real Arrow buffer_builder.h relies on. The vulnerable arithmetic in
// BufferBuilder is exercised unchanged; these macros only reproduce Arrow's
// status-propagation semantics.
#pragma once

#define NULLPTR nullptr

#define ARROW_PREDICT_FALSE(x) (x)
#define ARROW_PREDICT_TRUE(x) (x)

#define DCHECK(x) ((void)0)
#define DCHECK_OK(s) ((void)0)
#define DCHECK_LE(x, y) ((void)0)
#define DCHECK_NE(x, y) ((void)0)
#define DCHECK_GE(x, y) ((void)0)

#define ARROW_RETURN_NOT_OK(s)            \
  do {                                    \
    ::arrow::Status _status_ = (s);       \
    if (!_status_.ok()) {                 \
      return _status_;                    \
    }                                     \
  } while (0)

#define ARROW_ASSIGN_OR_RAISE(lhs, rhs)   \
  do {                                    \
    auto _result_ = (rhs);                \
    if (!_result_.ok()) {                 \
      return _result_.status();           \
    }                                     \
    lhs = std::move(_result_).ValueOrDie(); \
  } while (0)
