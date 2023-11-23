#ifndef __TOOLS_STATUS_H_
#define __TOOLS_STATUS_H_

namespace primihub::crypto {
class Status {
private:
  enum class Code {
    kOK = 0,
    kNetworkError,
    kMismatchError,
    kTimeoutError,
    kDuplicateError,
    kNotFoundError,
    kSyscallError,
    kInvalidError,
    kNotImplementError,
    kUnavailableError,
  };

public:
  virtual ~Status() = default;

  Status(const Status &rhs) = delete;
  Status &operator=(const Status &rhs) = delete;
  Status Copy() const { return Status(status_code_); }
  Status(Status &&rhs) = default;
  Status &operator=(Status &&rhs) = default;

  static Status OK() { return Status(Code::kOK); }
  static Status NetworkError() { return Status(Code::kNetworkError); }
  static Status MismatchError() { return Status(Code::kMismatchError); }
  static Status TimeoutError() { return Status(Code::kTimeoutError); }
  static Status DuplicateError() { return Status(Code::kDuplicateError); }
  static Status NotFoundError() { return Status(Code::kNotFoundError); }
  static Status SyscallError() { return Status(Code::kSyscallError); }
  static Status InvalidError() { return Status(Code::kInvalidError); }
  static Status NotImplementError() { return Status(Code::kNotImplementError); }
  static Status UnavailableError() { return Status(Code::kUnavailableError); }

  bool IsOK() const { return status_code_ == Code::kOK; }

private:
  explicit Status(const Code &status_code) : status_code_(status_code) {}

  Code status_code_;
};
} // namespace primihub::crypto

#endif
