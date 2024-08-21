// SPDX-License-Identifier: MIT
#ifndef FFKX_FILE_HPP
#define FFKX_FILE_HPP

#include <absl/status/statusor.h>
#include <fcntl.h>
#include <unistd.h>

#include <utility>

namespace ffkx {
namespace io {

class FileDescriptor {
 public:
  // Use zero as the invalid fd_ value, as we do not consider stdin a valid
  // descriptor to be managed using this class. This simplifies construction
  // as we can place this object on zeroed storage.
  constexpr explicit FileDescriptor(int fd = 0) : fd_(fd) {}
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;

  FileDescriptor(FileDescriptor&& rhs) noexcept { fd_ = std::exchange(rhs.fd_, 0); }
  FileDescriptor& operator=(FileDescriptor&& rhs) noexcept {
    if (this != &rhs) {
      fd_ = std::exchange(rhs.fd_, 0);
    }
    return *this;
  }

  ~FileDescriptor() {
    if (fd_) {
      close(fd_);
    }
  }

  [[nodiscard]] int Release() { return std::exchange(fd_, 0); }

  absl::StatusOr<FileDescriptor> Clone(int next_fd = 0);

  int GetRawFd() const { return fd_; }

 private:
  int fd_;
};

}  // namespace io
}  // namespace ffkx

#endif
