// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <ffkx_errno.bpf.h>
#include <ffkx_hashmap.bpf.h>
#include <ffkx_heap.bpf.h>
#include <ffkx_log.bpf.h>
#include <ffkx_malloc.bpf.h>
#include <ffkx_net.bpf.h>

// FIXME: Generate correct reply on ZADD, redis-zbench-go does not work

/// FNV HASH FIXME: Move to jhash header
#define FNV_OFFSET_BASIS_32 2166136261
#define FNV_PRIME_32 16777619

private(A) struct bpf_spin_lock lock;

ffkx_heap(256, 0) heap SEC(".maps");

bool ffkx_memcached_redis_mode = false;

// Heap

SEC("tc")
int ffkx_malloc_heap_base(struct __sk_buff *ctx) {
  void *map = &heap;
  ffkx_malloc_heap_kbase = ((struct bpf_map *)map)->kernel_base_addr;
  ffkx_malloc_heap_kmask = ((struct bpf_map *)map)->kernel_addr_mask;
  return 0;
}

struct ffkx_hashmap __hptr *ffkx_memcached_hashmap;
struct ffkx_hashmap_bucket *ffkx_memcached_hashmap_buckets;

uint64_t ffkx_memcached_hashmap_key_size;
uint64_t ffkx_memcached_hashmap_value_size;
uint64_t ffkx_memcached_hashmap_max_entries_size;
uint64_t ffkx_memcached_hashmap_nr_buckets;

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, __u64);
  __type(value, int);
  __uint(max_entries, 100000);
} sockhash SEC(".maps");

// Configuration options
// Destination port for Redis
const volatile int ffkx_memcached_dest_port = 6969;

enum {
  // ZERO INIT should set to this value
  FFKX_PKT_STATE_READ_CMD = 0,
  FFKX_PKT_STATE_READ_KEY,
  FFKX_PKT_STATE_READ_VALUE,
};

enum {
  FFKX_PKT_CMD_UNKNOWN,
  FFKX_PKT_CMD_GETS,
  FFKX_PKT_CMD_SETS,
};

struct ffkx_pkt_state_machine {
  int type;
  int count;
  int cmd;
  int key_cnt;
  int full_key_cnt;
  int val_cnt;
  u32 hash;
  void *value;
  u32 val_sz;
};

#define FFKX_MEMCACHED_KEY_BUF_SZ 1024

void *ffkx_memcached_key_buf;
void *ffkx_memcached_value_buf;

static inline void *get_kv_buf(void *buf) { return buf + (bpf_get_smp_processor_id() * FFKX_MEMCACHED_KEY_BUF_SZ); }

// INIT
SEC("tc")
int ffkx_memcached_hashmap_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);

  // Allocated by userspace
  auto map = ffkx_memcached_hashmap;
  auto buckets = ffkx_memcached_hashmap_buckets;

  ffkx_hashmap_init_key_size = ffkx_memcached_hashmap_key_size;
  ffkx_hashmap_init_value_size = ffkx_memcached_hashmap_value_size;
  ffkx_hashmap_init_max_entries = ffkx_memcached_hashmap_max_entries_size;

  if (!ffkx_memcached_hashmap_nr_buckets) {
    return ENOMEM;
  }
  return ffkx_hashmap_init(map, buckets, ffkx_memcached_hashmap_nr_buckets);
}

/// Packet state machine functions

// We reach here at start of the command, read until '\n'.
int __noinline ffkx_memcached_pkt_read_cmd(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  // Read until start of
  if (sm->count < 2) {
    if (c == '\n') {
      sm->count++;
    }
    ffkx_log_debug("seek until start of cmd");
    return FFKX_PKT_READ_CONT;
  }
  if (sm->count == 2) {
    if (c == 'G' || c == 'g') {
      sm->cmd = FFKX_PKT_CMD_GETS;
      sm->count++;
      ffkx_log_debug("Detected command GETS");
      return FFKX_PKT_READ_CONT;
    } else if (c == 'S' || c == 's') {
      sm->cmd = FFKX_PKT_CMD_SETS;
      sm->count++;
      ffkx_log_debug("Detected command SETS");
      return FFKX_PKT_READ_CONT;
    }
    // 3 is after seeing cmd char, 4 is after first newline, we do till new line
    // of key len.
  } else if (sm->count == 3 || sm->count == 4) {
    // Read until newline
    if (c != '\n') {
      return FFKX_PKT_READ_CONT;
    }
    sm->count++;
    // Second newline after cmd, parse key
    if (sm->count == 5) {
      sm->count = 0;
      sm->type = FFKX_PKT_STATE_READ_KEY;
    }
    return FFKX_PKT_READ_CONT;
  }
  ffkx_log_error("Unreachable condition for cmd sm->count=%d", sm->count);
  return -EINVAL;
}

int __noinline ffkx_memcached_pkt_read_key(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  if (!sm->key_cnt) sm->hash = FNV_OFFSET_BASIS_32;
  if (!sm->count && sm->cmd == FFKX_PKT_CMD_GETS) {
    if (c == '\r') {
      // Lookup and stash in sm.
      void *key = get_kv_buf(ffkx_memcached_key_buf);
      cast(void, key);
      auto lock = ffkx_hashmap_lock_bucket(ffkx_memcached_hashmap, sm->hash);
      if (!lock) return -EDEADLK;
      auto l = ffkx_hashmap_lookup_redis_elem(ffkx_memcached_hashmap, key, sm->key_cnt, sm->hash);
      bpf_spin_unlock(lock);
      ffkx_log_debug("Key=0x%llx", (u64)l);
      sm->value = l ? (l->buf + ffkx_round_up(l->key_size, 8)) : NULL;
      sm->val_sz = l ? l->value_size : 0;
      return FFKX_PKT_READ_DONE;
    }
    // Store char
    char *key = get_kv_buf(ffkx_memcached_key_buf) + sm->key_cnt;
    cast(void, key);
    *key = c;
    sm->key_cnt++;
    sm->hash ^= c;
    sm->hash *= FNV_PRIME_32;
    ffkx_log_debug("key=%c cnt=%d", c, sm->key_cnt);
    return FFKX_PKT_READ_CONT;
  } else if (!sm->count && sm->cmd == FFKX_PKT_CMD_SETS) {
    if (c == '\n') {
      sm->type = FFKX_PKT_STATE_READ_VALUE;
      sm->count = 0;
      return FFKX_PKT_READ_CONT;
    }
    // Ignore carriage
    if (c == '\r') return FFKX_PKT_READ_CONT;
    // Store char
    char *key = get_kv_buf(ffkx_memcached_key_buf) + sm->key_cnt;
    cast(void, key);
    *key = c;
    sm->key_cnt++;
    sm->hash ^= c;
    sm->hash *= FNV_PRIME_32;
    ffkx_log_debug("key=%c cnt=%d", c, sm->key_cnt);
    return FFKX_PKT_READ_CONT;
  }
  ffkx_log_error("Unimplemented rkey");
  return -EINVAL;
}

int __noinline ffkx_memcached_pkt_read_value(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  // Skip over length
  if (!sm->count) {
    if (c == '\n') sm->count++;
    return FFKX_PKT_READ_CONT;
  } else if (sm->count == 1) {
    // Got one key and value
    if (c == '\r') {
      auto ks = sm->key_cnt;
      auto vs = sm->val_cnt;
      // Reset transient state.
      sm->key_cnt = 0;
      sm->val_cnt = 0;
      sm->count = 0;

      auto key = get_kv_buf(ffkx_memcached_key_buf);
      cast(void, key);
      auto value = get_kv_buf(ffkx_memcached_value_buf);
      cast(void, value);
      auto lock = ffkx_hashmap_lock_bucket(ffkx_memcached_hashmap, sm->hash);
      if (!lock) return -EDEADLK;
      int ret = ffkx_hashmap_update_redis(ffkx_memcached_hashmap, key, ks, ffkx_conv_hptr(value), vs, sm->hash);
      bpf_spin_unlock(lock);
      if (ret < 0) {
        ffkx_log_error("Failed to perform hashmap update ret=%d", ret);
        return ret;
      }
      ffkx_log_debug("Added element to hashmap");
      ffkx_log_debug("Validation=%d",
                     !!ffkx_hashmap_lookup_redis(ffkx_memcached_hashmap, ffkx_conv_hptr(key), ks, sm->hash));
      // If no more key/values, don't complain
      return FFKX_PKT_READ_DONE;
    }
    // Copy to val buffer
    char *val = get_kv_buf(ffkx_memcached_value_buf) + sm->val_cnt;
    cast(void, val);
    *val = c;
    sm->val_cnt++;
    ffkx_log_debug("val=%c cnt=%d", c, sm->val_cnt);
    return FFKX_PKT_READ_CONT;
  }
  ffkx_log_error("Unimplemented value");
  return -EINVAL;
}

static __noinline int ffkx_memcached_pkt_read(char *buf, const int size, u32 *offp, void *userdata) {
  struct ffkx_pkt_state_machine *sm = userdata;
  int ret;

  int i;
  bpf_for(i, 0, size) {
    ++*offp;
    switch (sm->type) {
      case FFKX_PKT_STATE_READ_CMD:
        ret = ffkx_memcached_pkt_read_cmd(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      case FFKX_PKT_STATE_READ_KEY:
        ret = ffkx_memcached_pkt_read_key(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      case FFKX_PKT_STATE_READ_VALUE:
        ret = ffkx_memcached_pkt_read_value(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      default:
        return -ENOENT;
    }
  }
  return FFKX_PKT_READ_CONT;
}

struct action_write {
  int write_sets;
  int write_gets;
  void *value;
  u32 val_sz;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct action_write);
  __uint(max_entries, 1);
} action SEC(".maps");

SEC("sk_skb/stream_parser")
int ffkx_memcached_rx_stream_parser(struct __sk_buff *skb) {
  struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
  struct bpf_dynptr dptr;
  int len = skb->len;
  u64 cookie;
  u32 off;

  bpf_register_heap(&heap);

  // Obtain the unique socket cookie
  cookie = bpf_get_socket_cookie(skb);
  if (!cookie) {
    ffkx_pkt_log_error(skb, "Failed to obtain socket cookie.");
    return skb->len;
  }

  off = BPF_CORE_READ(skb_cb, strp.strp.offset);
  ffkx_pkt_log_debug(skb, "skb stats: length = %d, data_offset = %d.", len, off);

  int ret = 0;

  ret = ffkx_bpf_dynptr_from_skb(skb, 0, &dptr);
  if (ret < 0) {
    ffkx_pkt_log_error(skb, "Failed to create dynptr\n");
    return skb->len;
  }

  ret = -EFAULT;
  struct ffkx_pkt_state_machine sm = {0};
  ffkx_pkt_read_loop(&dptr, &off, &ret, ffkx_memcached_pkt_read, &sm);
  if (ret < 0 || ret != FFKX_PKT_READ_DONE) {
    ffkx_pkt_log_error(skb, "Failed to read packet: ret=%d", ret);
    return skb->len;
  }
  struct action_write *w = bpf_map_lookup_elem(&action, &(int){0});
  if (!w) {
    ffkx_pkt_log_error(skb, "Failed to do percpu map lookup");
    return skb->len;
  }
  switch (sm.cmd) {
    case FFKX_PKT_CMD_SETS:
      w->write_sets = 1;
      ffkx_log_debug("Sets done");
      break;
    case FFKX_PKT_CMD_GETS:
      w->write_gets = 1;
      w->value = sm.value;
      w->val_sz = sm.val_sz;
      ffkx_log_debug("Value=%d valsz=%d", w->value, w->val_sz);
      break;
    default:
      ffkx_pkt_log_error(skb, "Unknown pkt command");
      break;
  }
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int ffkx_memcached_rx_stream_verdict(struct __sk_buff *skb) {
  struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;

  u64 cookie = bpf_get_socket_cookie(skb);
  u32 off = BPF_CORE_READ(skb_cb, strp.strp.offset);
  int ret;
  struct action_write *w = bpf_map_lookup_elem(&action, &(int){0});
  if (!w) {
    ffkx_pkt_log_error(skb, "Failed to do percpu map lookup");
    return skb->len;
  }
  if (w->write_gets) {
    w->write_gets = 0;
    ret = bpf_skb_adjust_room(skb, 7 + 64 - skb->len, 0, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_adjust_room 11");
      return SK_PASS;
    }
#define _VAL_64(str) #str
#define VAL_64 _VAL_64(xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
    ret = bpf_skb_store_bytes(skb, off, "$64\r\n" VAL_64 "\r\n", 7 + 64, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_store_bytes 14");
      return SK_PASS;
    }
    ret = bpf_sk_redirect_hash(skb, &sockhash, &cookie, 0);
    if (ret != SK_PASS) {
      ffkx_pkt_log_error(skb, "Failed to redirect to sockhash");
      return SK_PASS;
    }
    return ret;
  } else if (w->write_sets) {
    w->write_sets = 0;
    ffkx_log_debug("We processed a SETS");
    ret = bpf_skb_adjust_room(skb, 5 - skb->len, 0, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_adjust_room 5");
      return SK_PASS;
    }
    ret = bpf_skb_store_bytes(skb, off, "+OK\r\n", 5, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_store_bytes 5");
      return SK_PASS;
    }
    ret = bpf_sk_redirect_hash(skb, &sockhash, &cookie, 0);
    if (ret != SK_PASS) {
      ffkx_pkt_log_error(skb, "Failed to redirect to sockhash");
      return SK_PASS;
    }
    return ret;
  }
  return SK_PASS;
}

SEC("sockops")
int ffkx_memcached_sockops(struct bpf_sock_ops *ctx) {
  int pid = bpf_get_current_task_btf()->tgid;
  int rport = bpf_ntohl(ctx->remote_port);
  struct bpf_sock *sk = ctx->sk;
  int lport = ctx->local_port;
  int op = ctx->op;

  switch (op) {
    default:
      break;
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
      ffkx_pkt_log_debug(sk, "SOCKOP TCP_LISTEN: pid=%d local_port=%d remote_port=%d", pid, lport, rport);
      break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
      ffkx_pkt_log_debug(sk, "SOCKOP PASSIVE_ESTABLISHED: pid=%d local_port=%d remote_port=%d", pid, lport, rport);
      break;
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
      ffkx_pkt_log_debug(sk, "SOCKOP TCP_CONNECT: pid=%d local_port=%d remote_port=%d", pid, lport, rport);
      break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
      ffkx_pkt_log_debug(sk, "SOCKOP ACTIVE_ESTABLISHED: pid=%d local_port=%d remote_port=%d", pid, lport, rport);
      break;
  }

  if (lport == ffkx_memcached_dest_port && op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
    u64 cookie = bpf_get_socket_cookie(ctx);
    int ret;

    // Userspace fallback needs to use socket cookie identifier.
    ret = bpf_sock_hash_update(ctx, &sockhash, &cookie, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(sk, "Failed to add socket to SOCKHASH map: %d", ret);
      return 0;
    }
    ffkx_pkt_log_debug(sk, "SOCKOP SOCK ADDED: pid=%d cookie=%d local_port=%d remote_port=%d sk_rcvbuf=%d", pid, cookie,
                       lport, rport, BPF_CORE_READ((struct sk_buff *)ctx, sk, sk_rcvbuf));
  }
  return 1;
}

char _license[] SEC("license") = "GPL";
/*
// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <ffkx_hashmap.bpf.h>
#include <ffkx_heap.bpf.h>
#include <ffkx_log.bpf.h>
#include <ffkx_malloc.bpf.h>
#include <ffkx_net.bpf.h>

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

struct ffkx_memcached_ctx {
  u32 off;
  u32 len;
};

// Configuration options
// Destination port for memcached
const volatile int ffkx_memcached_dest_port = 11211;

ffkx_heap(16, 0) heap SEC(".maps");

// Hashmap
struct ffkx_hashmap __hptr *ffkx_memcached_hashmap;
struct ffkx_hashmap_bucket __hptr *ffkx_memcached_hashmap_buckets;
uint64_t ffkx_memcached_hashmap_nr_buckets;

uint32_t ffkx_hashmap_key_size;
uint32_t ffkx_hashmap_value_size;
uint32_t ffkx_hashmap_max_entries;

SEC("tc")
int ffkx_memcached_hashmap_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);

  // Allocated by userspace
  auto map = ffkx_memcached_hashmap;
  auto buckets = ffkx_memcached_hashmap_buckets;

  ffkx_hashmap_init_key_size = ffkx_hashmap_key_size;
  ffkx_hashmap_init_value_size = ffkx_hashmap_value_size;
  ffkx_hashmap_init_max_entries = ffkx_hashmap_max_entries;

  if (!map || !buckets || !ffkx_memcached_hashmap_nr_buckets) {
    return EINVAL;
  }
  int ret = ffkx_hashmap_init(map, buckets, ffkx_memcached_hashmap_nr_buckets);
  if (ret < 0) {
    return -ret;
  }
  return 0;
}

static __always_inline bool ffkx_memcached_cmd_is_get(const char *cmd) {
  return cmd[0] == 'g' && cmd[1] == 'e' && cmd[2] == 't' && cmd[3] == ' ';
}

static __always_inline u16 ffkx_compute_ip_checksum(struct iphdr *ip) {
  u16 *next_ip_u16 = (u16 *)ip;
  u32 csum = 0;

  ip->check = 0;

#pragma clang loop unroll(full)
  for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
    csum += *next_ip_u16++;
  }

  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  return (uint16_t)~csum;
}
struct ffkx_parse_key {};

static __noinline int ffkx_memcached_parse_key_bytes(char *buf, const int size, u32 *offp, void *userdata) {
  for (int i = 0; i < size; i++) {
    ++*offp;
    if (buf[i] != ' ' && buf[i] != '\r') {
      // copy
      continue;
    } else {
      ret = FFKX_PKT_READ_DONE;
    }
    if
  }
}

int ffkx_memcached_parse_key(struct xdp_md *ctx, struct ffkx_memcached_ctx *mctx) {
  struct bpf_dynptr dptr;
  bool done = false;
  int ret;

  ret = ffkx_bpf_dynptr_from_xdp(ctx, 0, &dptr);
  if (ret < 0) {
    ffkx_pkt_log_error(ctx, "Failed to create dynptr from xdp ctx");
    return ret;
  }

  ffkx_pkt_read_loop(&dptr, &mctx->off, &ret, ffkx_memcached_parse_key_bytes, &data);
  if (ret < 0) {
    ffkx_pkt_log_error("Failing to read key bytes: ret=%d", ret);
    return ret;
  }
}

static __always_inline int ffkx_memcached_process_get(struct xdp_md *ctx, struct ffkx_memcached_ctx *mctx, void *data,
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
    return -EINVAL;
  }
  cmd = data;

  if (!ffkx_memcached_cmd_is_get(cmd)) {
    ffkx_pkt_log_error(ctx, "Failed to handle non-GET command over UDP");
    return -EINVAL;
  }
  data += 4;
  mctx->off += 4;

  if (data == data_end) {
    ffkx_pkt_log_error(ctx, "GET request is malformed, no key available after the command");
    return -EINVAL;
  }

  int ret = bpf_xdp_adjust_head(ctx, mctx->off);
  if (ret < 0) {
    ffkx_pkt_log_error(ctx, "Failed to do bpf_xdp_adjust_head ret=%d", ret);
    return ret;
  }

  // FIXME: We must skip over whitespace after get, we already skipped over one,
  // but there might be more. It is legal as per memcached protocol.
  if (data + 1 > data_end && *(char *)data == ' ') {
    ffkx_pkt_log_error(ctx, "Failed to handle extra whitespace after 'get' command");
    return -EINVAL;
  }

  ret = ffkx_memcached_parse_key(ctx, mctx);
  return XDP_REDIRECT;
}

SEC("xdp")
int ffkx_memcached_rx_xdp(struct xdp_md *ctx) {
  u32 len = (long)ctx->data_end - (long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ffkx_memcached_ctx mctx = {0};
  int protocol, dport, ret;
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
    return XDP_PASS;
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
      ret = ffkx_memcached_process_get(ctx, &mctx, data, data_end);
      if (ret < 0) {
        return XDP_PASS;
      }
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
*/
