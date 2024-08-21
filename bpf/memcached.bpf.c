// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <ffkx_hashmap.bpf.h>
#include <ffkx_log.bpf.h>
#include <ffkx_malloc.bpf.h>
#include <ffkx_net.bpf.h>

struct ffkx_memcached_value {
  u32 key_len;
  u32 value_len;
  char buf[];
};

struct ffkx_memcached_ctx {
  u32 off;
  u32 len;
};

struct ffkx_memcached_key_ctx {
  u32 hash;
  u32 len;
  bool done;
};

// TODO(kkd): We only work with single key GETs, not multi-key GETs
//            This implies support for multiple whitespace separated keys before \r\n.
// TODO(kkd): Likewise, for the responses, multiple key-value pairs are not supported
//            VALUE <key> <flags> <bytes> [<cas unique>]\r\ndata\r\n over and over for each key until END\r\n.

// TODO(kkd): memcached_udp_header
#define MEMCACHED_UDP_HDR_SZ 8

#define FFKX_MEMCACHED_MAX_KEY_SZ 256
#define FFKX_MEMCACHED_MAX_VAL_SZ 1024
#define FFKX_MEMCACHED_MAX_ADDITIONAL_SZ 53
#define FFKX_MEMCACHED_CACHE_VALUE_SZ \
  (FFKX_MEMCACHED_MAX_KEY_SZ + FFKX_MEMCACHED_MAX_VAL_SZ + FFKX_MEMCACHED_MAX_ADDITIONAL_SZ)
#define FFKX_MEMCACHED_MAX_KEY_IN_MULTIGET 30
// cache entry count / 10 for now
#define FFKX_MEMCACHED_CACHE_ENTRY_COUNT (3250000 / 10)
// #define FFKX_MEMCACHED_CACHE_ENTRY_COUNT 3250000
#define FFKX_MEMCACHED_MAX_PACKET_LENGTH 1500
#define FFKX_MEMCACHED_MAX_KEY_IN_PACKET FFKX_MEMCACHED_MAX_KEY_IN_MULTIGET

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, __u64);
  __type(value, int);
  __uint(max_entries, 4096);
} sockhash SEC(".maps");

// Configuration options
// Destination port for memcached
const volatile int ffkx_memcached_dest_port = 11211;

static __always_inline bool ffkx_memcached_cmd_is_get(const char *cmd) {
  return cmd[0] == 'g' && cmd[1] == 'e' && cmd[2] == 't' && cmd[3] == ' ';
}

static __always_inline int ffkx_process_memcached_key_find_set(struct xdp_md *ctx, struct ffkx_memcached_value *value) {
  char *data_end = (void *)(long)ctx->data_end;
  char *data = (void *)(long)ctx->data;

  data += sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MEMCACHED_UDP_HDR_SZ;

  for (int i = 0; i < FFKX_MEMCACHED_MAX_KEY_SZ; i++) {
    if (data + i + 1 > data_end) {
      break;
    }
    if (value->key[i] != data[i]) {
      return 1;
    }
  }
  return 0;
}

static __always_inline int ffkx_process_memcached_copy_value(struct xdp_md *ctx, struct ffkx_memcached_value *value) {
  const u32 off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MEMCACHED_UDP_HDR_SZ;
  char *data_end = (void *)(long)ctx->data_end;
  char *old_data = (void *)(long)ctx->data;
  char *data = old_data;

  data += sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MEMCACHED_UDP_HDR_SZ;
  if (data + 6 > data_end) {
    return FFKX_NET_ACT_PASS;
  }
  data[0] = 'V';
  data[1] = 'A';
  data[2] = 'L';
  data[3] = 'U';
  data[4] = 'E';
  data[5] = ' ';
  data += 6;

  // 6 for 'VALUE ', 5 for 'END\r\n'
  /* TODO(allow this function)
  if (bpf_xdp_adjust_tail(ctx, off + 6 + value->value_len + 5 - (data_end - old_data))) {
    // ffkx_pkt_log_debug(ctx, "Failed to adjust XDP packet tail, old=%d new=%d", data_end - old_data, off +
  value->value_len); return FFKX_NET_ACT_PASS;
  }
  */

  data_end = (void *)(long)ctx->data_end;
  data = (void *)(long)ctx->data;
  // TODO(allow adjust tail and copy full length)
  // int i
  int i;
  for (i = 0; i < 5; i++) {  // FFKX_MEMCACHED_MAX_VAL_SZ; i++) {
    if (data + off + i + 1 > data_end) {
      // ffkx_pkt_log_debug(ctx, "Failed to find more room in XDP packet off=%d i=%d", off, i);
      return FFKX_NET_ACT_PASS;
    }
    data[off + i] = value->value[i];
  }

  data += off + i;
  if (data + 5 > data_end) {
    return FFKX_NET_ACT_PASS;
  }
  data[0] = 'E';
  data[1] = 'N';
  data[2] = 'D';
  data[3] = '\r';
  data[4] = '\n';
  return FFKX_NET_ACT_OK;
}

static __noinline int ffkx_process_memcached_key_lookup(struct xdp_md *ctx,
                                                        struct ffkx_memcached_value_set *value_set) {
  struct ffkx_memcached_value *value;
  int ret;

  bpf_spin_lock(&value_set->lock);
  for (int i = 0; i < sizeof(value_set->set) / sizeof(value_set->set[0]); i++) {
    value = &value_set->set[i];
    if (ffkx_process_memcached_key_find_set(ctx, value)) {
      break;
    }
  }

  ret = ffkx_process_memcached_copy_value(ctx, value);
  bpf_spin_unlock(&value_set->lock);
  return ret;
}

static __noinline

    int
    ffkx_process_memcached_key(struct xdp_md *ctx, struct ffkx_memcached_ctx *mctx) {
  struct ffkx_memcached_key_ctx kctx = {};
  struct bpf_dynptr ptr;
  char buf[256];
  u32 rem_len;
  void *data;
  int ret;

  if (!mctx) {
    ffkx_pkt_log_error(ctx, "NULL pointer for mctx");
    return FFKX_NET_ACT_PASS;
  }

  kctx.hash = FNV_OFFSET_BASIS_32;
  rem_len = mctx->len - mctx->off;

  if (rem_len > FFKX_MEMCACHED_MAX_KEY_SZ) {
    ffkx_pkt_log_error(ctx, "Key too big in GET command: len=%d max=%d", rem_len, FFKX_MEMCACHED_MAX_KEY_SZ);
    return FFKX_NET_ACT_PASS;
  }

  ret = ffkx_bpf_dynptr_from_xdp(ctx, 0, &ptr);
  if (ret < 0) {
    ffkx_pkt_log_error(ctx, "Failed to create dynamic pointer for xdp_md");
    return FFKX_NET_ACT_PASS;
  }

  bpf_repeat(BPF_MAX_LOOPS) {
    u32 cur_off = mctx->off;

    if (!rem_len) {
      break;
    }

    if (rem_len >= 256) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 256);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 256, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_256(data, &kctx, &mctx->off);
    } else if (rem_len >= 128) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 128);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 128, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_128(data, &kctx, &mctx->off);
    } else if (rem_len >= 64) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 64);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 64, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_64(data, &kctx, &mctx->off);
    } else if (rem_len >= 32) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 32);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 32, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_32(data, &kctx, &mctx->off);
    } else if (rem_len >= 16) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 16);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 16, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_16(data, &kctx, &mctx->off);
    } else if (rem_len >= 8) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 8);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 8, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_8(data, &kctx, &mctx->off);
    } else if (rem_len >= 4) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 4);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 4, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_4(data, &kctx, &mctx->off);
    } else if (rem_len >= 1) {
      data = ffkx_bpf_dynptr_slice_rdwr(&ptr, mctx->off, buf, 1);
      if (!data) {
        ffkx_pkt_log_debug(ctx, "Failed to obtain packet slice for off=%d size=%d rem_len=%d", mctx->off, 1, rem_len);
        return FFKX_NET_ACT_PASS;
      }
      ffkx_process_memcached_data_1(data, &kctx, &mctx->off);
    }
    rem_len -= mctx->off - cur_off;
    if (!rem_len || kctx.done) break;
  }

  if (!kctx.done || kctx.len == 0 || kctx.len > FFKX_MEMCACHED_MAX_KEY_SZ) {
    ffkx_pkt_log_debug(ctx, "Failed to process key, done=%d len=%d max=%d", kctx.done, kctx.len,
                       FFKX_MEMCACHED_MAX_KEY_SZ);
    return FFKX_NET_ACT_PASS;
  }

  kctx.hash %= FFKX_MEMCACHED_CACHE_ENTRY_COUNT;
  struct ffkx_memcached_value_set *value_set = bpf_map_lookup_elem(&ffkx_memcache, &kctx.hash);
  if (!value_set) {
    ffkx_pkt_log_debug(ctx, "Failed to obtain cache value for kctx.hash=%u", kctx.hash);
    return FFKX_NET_ACT_PASS;
  }

  return ffkx_process_memcached_key_lookup(ctx, value_set);
}

static __always_inline int ffkx_process_memcached_get(struct xdp_md *ctx, struct ffkx_memcached_ctx *mctx, void *data,
                                                      void *data_end) {
  struct udphdr *udph;
  char *cmd;
  int dport;

  udph = data;
  if (udph + 1 > data_end) {
    ffkx_pkt_log_debug(ctx, "Failed to read UDP header bytes");
    return -EINVAL;
  }

  dport = udph->dest;
  if (dport != bpf_htons(ffkx_memcached_dest_port)) {
    ffkx_pkt_log_debug(ctx, "UDP packet dport mismatch: dport=%d memcached_dport=%d", dport, ffkx_memcached_dest_port);
    return -EINVAL;
  }
  data += sizeof(struct udphdr) + MEMCACHED_UDP_HDR_SZ;
  mctx->off += sizeof(struct udphdr) + MEMCACHED_UDP_HDR_SZ;

  if (data + 4 > data_end) {
    ffkx_pkt_log_error(ctx, "Failed to read memcached GET command bytes");
    return FFKX_NET_ACT_PASS;
  }
  cmd = data;

  if (!ffkx_memcached_cmd_is_get(cmd)) {
    ffkx_pkt_log_error(ctx, "Failed to handle non-GET command over UDP");
    return FFKX_NET_ACT_PASS;
  }
  data += 4;
  mctx->off += 4;

  if (data == data_end) {
    ffkx_pkt_log_error(ctx, "GET request is malformed, no key available after the command");
    return FFKX_NET_ACT_PASS;
  }

  // TODO(kkd): We should be more careful here to seek until we find non ' '
  // character, but for now, all tools we encounter do the right thing, so
  // simply parse the key starting from this offset.
  return ffkx_process_memcached_key(ctx, mctx);
}

SEC("xdp")
int ffkx_memcached_rx_xdp(struct xdp_md *ctx) {
  u32 len = (long)ctx->data_end - (long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ffkx_memcached_ctx mctx = {0};
  int protocol, dport, act, ret;
  struct udphdr *udph;
  struct tcphdr *tcph;
  unsigned int nh_off;
  struct ethhdr *eth;
  struct iphdr *iph;

  // Set total length for packet in context
  mctx.len = len;

  // Process L2
  eth = data;
  if (eth + 1 > data_end) {
    ffkx_pkt_log_debug(ctx, "Failed to read ethernet header bytes");
    return FFKX_NET_ACT_PASS;
  }
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    ffkx_pkt_log_debug(ctx, "Unknown ethernet protocol %d", eth->h_proto);
    return XDP_PASS;
  }
  // Advance cursor and offset
  data += sizeof(struct ethhdr);
  mctx.off += sizeof(struct ethhdr);

  // Process L3
  iph = data;
  if (iph + 1 > data_end) {
    ffkx_pkt_log_debug(ctx, "Failed to read IPv4 header bytes");
    return XDP_PASS;
  }
  protocol = iph->protocol;
  // Advance cursor and offset
  data += sizeof(struct iphdr);
  mctx.off += sizeof(struct iphdr);

  // Choose handler for the IP protocol
  switch (protocol) {
    case IPPROTO_UDP:
      act = ffkx_process_memcached_get(ctx, &mctx, data, data_end);
      break;
    case IPPROTO_TCP:
      // Pass the packet to our sk_skb handler
      return XDP_PASS;
    default:
      ffkx_pkt_log_debug(ctx, "Unknown IP protocol");
      return XDP_PASS;
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
