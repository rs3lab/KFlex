// SPDX-License-Identifier: MIT
#ifndef FFKX_SOCKET_HPP
#define FFKX_SOCKET_HPP

#include <absl/status/statusor.h>
#include <unistd.h>

#include <File.hpp>

namespace ffkx {
namespace net {

class Socket : public io::FileDescriptor {
 public:
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  Socket(Socket&&) = default;
  Socket& operator=(Socket&&) = default;
  ~Socket() = default;

  using io::FileDescriptor::Clone;
  using io::FileDescriptor::GetRawFd;
  using io::FileDescriptor::Release;

  absl::Status SetRxBufferSize(size_t size);
  absl::Status SetTxBufferSize(size_t size);
  absl::Status BindAny(int port);
  absl::Status SetListen(int backlog);
  absl::StatusOr<io::FileDescriptor> AcceptConnection();

  static absl::StatusOr<Socket> MakeTCP();

 private:
  Socket(io::FileDescriptor fd) : io::FileDescriptor(std::move(fd)) {}
};

}  // namespace net
}  // namespace ffkx

#endif
