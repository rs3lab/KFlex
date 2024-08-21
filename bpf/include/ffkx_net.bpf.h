// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_NET_BPF_H
#define FFKX_BPF_FFKX_NET_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_helpers.h>
#include <ffkx_util.bpf.h>

// Constants for Ethernet
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

// Constants for TC hook
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

int bpf_dynptr_from_xdp(struct xdp_buff *xdp, u64 flags, struct bpf_dynptr_kern *ptr) __ksym;
int bpf_dynptr_from_skb(struct sk_buff *skb, u64 flags, struct bpf_dynptr_kern *ptr) __ksym;
void *bpf_dynptr_slice(const struct bpf_dynptr_kern *ptr, u32 offset, void *buffer, u32 buffer_sz) __ksym;
void *bpf_dynptr_slice_rdwr(const struct bpf_dynptr_kern *ptr, u32 offset, void *buffer, u32 buffer_sz) __ksym;

static __always_inline int ffkx_bpf_dynptr_from_xdp(struct xdp_md *xdp, u64 flags, struct bpf_dynptr *dptr) {
  return bpf_dynptr_from_xdp((struct xdp_buff *)xdp, flags, (struct bpf_dynptr_kern *)dptr);
}

static __always_inline int ffkx_bpf_dynptr_from_skb(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *dptr) {
  return bpf_dynptr_from_skb((struct sk_buff *)skb, flags, (struct bpf_dynptr_kern *)dptr);
}

static __always_inline void *ffkx_bpf_dynptr_slice(const struct bpf_dynptr *ptr, u32 off, void *buf, u32 buf_sz) {
  return bpf_dynptr_slice((const struct bpf_dynptr_kern *)ptr, off, buf, buf_sz);
}

static __always_inline void *ffkx_bpf_dynptr_slice_rdwr(const struct bpf_dynptr *ptr, u32 off, void *buf, u32 buf_sz) {
  return bpf_dynptr_slice_rdwr((const struct bpf_dynptr_kern *)ptr, off, buf, buf_sz);
}

enum {
  FFKX_PKT_READ_CONT = 0,
  FFKX_PKT_READ_DONE = 1,
  FFKX_PKT_READ_BNDR = 2,  // This means that the packet if it ends now is not
                           // problematic
  // Return non-zero or less than zero to indicate break and error
};

// FIXME: Increase stack buffer size
#define ffkx_pkt_read_loop(dptr, offp, retp, cb, userdata)                      \
  ({                                                                            \
    int __it = 0;                                                               \
    __it = scalar_cast(__it);                                                   \
    ffkx_loop {                                                                  \
      __it++;                                                                   \
      if (__it > 100000) {                                                      \
        *retp = -EDEADLK;                                                       \
        break;                                                                  \
      }                                                                         \
      __it = scalar_cast(__it);                                                 \
      char __rdwrbuf[64];                                                       \
      char *buf;                                                                \
      buf = ffkx_bpf_dynptr_slice_rdwr(dptr, *(offp), __rdwrbuf, 64);           \
      int size = 64;                                                            \
      if (!buf) {                                                               \
        buf = ffkx_bpf_dynptr_slice_rdwr(dptr, *(offp), __rdwrbuf, 1);          \
        size = 1;                                                               \
        if (!buf) {                                                             \
          /* If the previous retval was a boundary of message, it's fine if     \
           * packet has ran out of space.*/                                     \
          *retp = (*retp == FFKX_PKT_READ_BNDR) ? FFKX_PKT_READ_DONE : -ENOSPC; \
          break;                                                                \
        }                                                                       \
        if ((*retp = cb(buf, 1, (offp), userdata))) {                           \
          /* Break the loop if it's not a boundary condition. */                \
          if (*retp != FFKX_PKT_READ_BNDR) {                                    \
            break;                                                              \
          }                                                                     \
        }                                                                       \
        continue;                                                               \
      }                                                                         \
      if ((*retp = cb(buf, 64, (offp), userdata))) {                            \
        /* Break the loop if it's not a boundary condition. */                  \
        if (*retp != FFKX_PKT_READ_BNDR) {                                      \
          break;                                                                \
        }                                                                       \
      }                                                                         \
    }                                                                           \
  })
#endif
