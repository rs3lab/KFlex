// SPDX-License-Identifier: MIT
#include <absl/status/statusor.h>
#include <absl/strings/str_format.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <Socket.hpp>

namespace ffkx {
namespace net {

absl::Status Socket::SetRxBufferSize(size_t size) {
  int fd = GetRawFd();
  int sz = size;
  int err = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
  if (err < 0) {
    return absl::ErrnoToStatus(errno, absl::StrFormat("Failed to set SO_RCVBUFFORCE option size (%d).", sz));
  }
  return absl::OkStatus();
}

absl::Status Socket::SetTxBufferSize(size_t size) {
  int fd = GetRawFd();
  int sz = size;
  int err = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sz, sizeof(sz));
  if (err < 0) {
    return absl::ErrnoToStatus(errno, absl::StrFormat("Failed to set SO_SNDBUFFORCE option size (%d).", sz));
  }
  return absl::OkStatus();
}

absl::Status Socket::BindAny(int port) {
  struct sockaddr_in server_addr;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  int err = bind(GetRawFd(), reinterpret_cast<struct sockaddr *>(&server_addr), sizeof(server_addr));
  if (err < 0) {
    return absl::ErrnoToStatus(errno, absl::StrFormat("Failed to bind socket to port %d.", port));
  }
  return absl::OkStatus();
}

absl::Status Socket::SetListen(int backlog) {
  int err = listen(GetRawFd(), backlog);
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to listen on the TCP socket.");
  }
  return absl::OkStatus();
}

absl::StatusOr<io::FileDescriptor> Socket::AcceptConnection() {
  int accept_fd = accept4(GetRawFd(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
  if (accept_fd < 0) {
    return absl::ErrnoToStatus(errno, "Failed to accept connection from socket.");
  }
  return io::FileDescriptor(accept_fd);
}

absl::StatusOr<Socket> Socket::MakeTCP() {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    return absl::ErrnoToStatus(errno, "Failed to create TCP stream socket.");
  }
  io::FileDescriptor fd(server_fd);
  int opt = 1;
  int err = setsockopt(fd.GetRawFd(), IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to set TCP_NODELAY option.");
  }
  int optval = 1;
  err = setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
  if (err < 0) {
    return absl::ErrnoToStatus(errno, "Failed to set SO_REUSEPORT option.");
  }
  return Socket(std::move(fd));
}

}  // namespace net
}  // namespace ffkx
