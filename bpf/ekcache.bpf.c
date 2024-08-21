// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

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

// Destination port on the receive hook
const volatile int ekcache_rx_dest_port;
// Passthrough mode
const volatile int ekcache_mode_passthrough;
// Logging verbosity
const volatile int ekcache_log_verbose = 0;

#define verbose(...)         \
  if (ekcache_log_verbose) { \
    bpf_printk(__VA_ARGS__); \
  }

#define defval "xxxxxxxxxxxxxxxx\r\n"

// kfunc declarations
void *bpf_dynptr_slice(const struct bpf_dynptr_kern *ptr, u32 offset, void *buffer, u32 buffer_sz) __ksym;
int bpf_dynptr_from_skb(struct sk_buff *skb, u64 flags, struct bpf_dynptr_kern *ptr) __ksym;

static __always_inline void *ekcache_dynptr_slice(const struct bpf_dynptr *ptr, u32 offset, void *buffer,
                                                  u32 buffer_sz) {
  struct bpf_dynptr_kern *dptr = (void *)ptr;

  return bpf_dynptr_slice(dptr, offset, buffer, buffer_sz);
}

static __always_inline int ekcache_dynptr_from_skb(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *ptr) {
  struct bpf_dynptr_kern *dptr = (void *)ptr;
  struct sk_buff *skbp = (void *)skb;

  return bpf_dynptr_from_skb(skbp, flags, dptr);
}

static __always_inline bool ekcache_is_memcache_get_request(char *cmd) {
  return cmd[0] == 'g' && cmd[1] == 'e' && cmd[2] == 't' && cmd[3] == '\0';
}

static __always_inline bool ekcache_is_redis_set_request(char *cmd) {
  return cmd[0] == '*' && cmd[1] == '3' && cmd[2] == '\r' && cmd[3] == '\n' && cmd[4] == '$' && cmd[5] == '3' &&
         cmd[6] == '\r' && cmd[7] == '\n' && cmd[8] == 'S' && cmd[9] == 'E' && cmd[10] == 'T' && cmd[11] == '\r' &&
         cmd[12] == '\n';
}

static __always_inline bool ekcache_is_redis_get_request(char *cmd) {
  return cmd[0] == '*' && cmd[1] == '2' && cmd[2] == '\r' && cmd[3] == '\n' && cmd[4] == '$' && cmd[5] == '3' &&
         cmd[6] == '\r' && cmd[7] == '\n' && cmd[8] == 'G' && cmd[9] == 'E' && cmd[10] == 'T' && cmd[11] == '\r' &&
         cmd[12] == '\n';
}

struct ekcache_sk_state {
  int data;
};

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 4096);
} sockmap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, __u64);
  __type(value, int);
  __uint(max_entries, 4096);
} sockhash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, u64);
  __type(value, struct ekcache_sk_state);
  __uint(max_entries, 4096);
} sk_hashmap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct keyval {
  char key[64];
  char val[64];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct keyval);
  __uint(max_entries, 1000000);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} hashmap SEC(".maps");

static __always_inline void ekcache_recompute_pkt_pointers(struct __sk_buff *ctx, void **datap, void **data_endp) {
  *data_endp = (void *)(long)ctx->data_end;
  *datap = (void *)(long)ctx->data;
}
/*
SEC("tc")
int ekcache_udp_parser_tc(struct __sk_buff *ctx) {
  struct bpf_dynptr skb;
  void *data, *data_end;
  struct udphdr *udph;
  struct tcphdr *tcph;
  struct ethhdr *eth;
  struct iphdr *iph;
  void *payload;
  int dport;
  int err;

  ekcache_recompute_pkt_pointers(ctx, &data, &data_end);

  eth = data;
  iph = data + sizeof(*eth);
  udph = data + sizeof(*eth) + sizeof(*iph);
  tcph = data + sizeof(*eth) + sizeof(*iph);

  if (iph + 1 > data_end) {
    return TC_ACT_OK;
  }

  switch (iph->protocol) {
    case IPPROTO_UDP:
      if (udph + 1 > data_end) {
        return TC_ACT_OK;
      }
      dport = udph->dest;
      payload = udph + 1;  // Add memcached UDP header for UDP mode
      break;
    case IPPROTO_TCP:
      if (tcph + 1 > data_end) {
        return TC_ACT_OK;
      }
      dport = tcph->dest;
      payload = tcph + 1;
      break;
  }

  // Check if this packet is destined for our socket.
  if (dport != ekcache_rx_dest_port) {
    return TC_ACT_OK;
  }

  // Protocol check?
  if (payload + 4 <= data_end) {
    if (!ekcache_is_memcache_get_request(payload)) {
      // Form dynptr otherwise
      return TC_ACT_SHOT;
    }
  }

  err = ekcache_dynptr_from_skb(ctx, 0, &skb);
  if (err < 0) {
    verbose("Failed to form skb dynptr: %d\n", err);
    return TC_ACT_OK;
  }
  return TC_ACT_OK;
}
*/

SEC("sk_skb/stream_parser")
int ekcache_tcp_stream_parser_skb(struct __sk_buff *skb) {
  struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
  enum { SET, GET, _NONE } req = _NONE;
  struct ekcache_sk_state *st;
  int len = skb->len;
  struct keyval_ctx {
    char buf[64];
    char value[64];
  } kv = {};
  u64 cookie;

  // Obtain the unique socket cookie
  cookie = bpf_get_socket_cookie(skb);
  if (!cookie) {
    verbose("Failed to obtain socket cookie.");
    goto fail;
  }

  // Lookup the socket state
  st = bpf_map_lookup_elem(&sk_hashmap, &cookie);
  if (!st) {
    // This should not really happen, as we use the sockops hook to insert the
    // socket in the sockhash in a race free fashion, and create its state
    // there. However, on machines with cgroupsv1, we go for a fallback solution
    // which is racy. Hence, create and lookup the state here again.
    struct ekcache_sk_state state = {};
    verbose("Warning: Failed to find socket state in sk_hashmap!");
    verbose("This must be populated by sockops hook, things race otherwise.");

    int ret = bpf_map_update_elem(&sk_hashmap, &cookie, &state, BPF_NOEXIST);
    st = bpf_map_lookup_elem(&sk_hashmap, &cookie);
    if (ret < 0 || !st) {
      verbose("Failed to create sk_hashmap entry for socket cookie.");
      goto fail;
    }
  }

  int data_offset = BPF_CORE_READ(skb_cb, strp.strp.offset);
  verbose("skb stats: length = %d, data_offset = %d.", len, data_offset);
  /* Parse: *X\r\n$3\r\nSET\r\n */
  int ret = bpf_skb_load_bytes(skb, data_offset, kv.buf, 13);
  if (ret < 0) {
    verbose("Failed to load data from skb: %d.", ret);
    goto end;
  }

  verbose("Packet header: %s", kv.buf);

  if (ekcache_is_redis_set_request(kv.buf)) {
    verbose("Detected SET request.");
    req = SET;
  } else if (ekcache_is_redis_get_request(kv.buf)) {
    verbose("Detected GET request.");
    req = GET;
  }

  if (ekcache_mode_passthrough) {
    goto end;
  }

  ret = bpf_skb_load_bytes(skb, data_offset + 13 + 4 /* $7\r\n */, kv.buf, 9);
  if (ret < 0) {
    verbose("Failed to load key data from skb: %d.", ret);
    goto end;
  }
  kv.buf[9] = '\0';

  if (req == SET) {
    __builtin_memcpy(kv.value, "xxxxxxxxxxxxxxxx\r\n", 19);
    ret = bpf_map_update_elem(&hashmap, kv.buf, &kv, 0);
    if (ret < 0) {
      verbose("Failed to insert entry into hashmap: %d.", ret);
    }
  }

  ret = bpf_skb_pull_data(skb, skb->len);
  if (ret < 0) {
    verbose("Failed to pull skb to len %d.", skb->len);
    goto end;
  }
  void *data, *data_end;
  ekcache_recompute_pkt_pointers(skb, &data, &data_end);
  if (req == SET) {
    verbose("Handle SET...");
    struct keyval *val = bpf_map_lookup_elem(&hashmap, kv.buf);
    if (!val) {
      verbose("Failed lookup for inserted key.");
      goto end;
    }
    verbose("Key: %s", val->key);
    verbose("Value: %s", val->val);

    st->data = 1;
    return len;
  } else if (req == GET) {
    verbose("Handle GET...");
    struct keyval *val = bpf_map_lookup_elem(&hashmap, kv.buf);
    if (!val) {
      verbose("Cannot find key, writing nil response.");

      st->data = 2;
      return len;
    }
    verbose("Key: %s", val->key);
    verbose("Value: %s", val->val);

    st->data = 3;
    return len;
  }
end:
  verbose("Failed something...");
  return skb->len;
fail:
  verbose("Failure in stream parser");
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int ekcache_tcp_stream_verdict_skb(struct __sk_buff *skb) {
  struct ekcache_sk_state *st;
  struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;
  u64 cookie;

  cookie = bpf_get_socket_cookie(skb);
  st = bpf_map_lookup_elem(&sk_hashmap, &cookie);
  if (!st) {
    verbose("Failed to find socket related state in sk_hashmap.");
    return SK_PASS;
  }

  void *data, *data_end;
  int len = skb->len;
  if (st->data == 1 || st->data == 2) {
    int ret = bpf_skb_adjust_room(skb, 5 - len, 0, 0);
    if (ret < 0) {
      verbose("Failed to grow or shrink tail room by %d: %d.", 5 - len, ret);
      return SK_PASS;
    }

    ekcache_recompute_pkt_pointers(skb, &data, &data_end);
    if (data + 5 > data_end) return SK_PASS;
    __builtin_memcpy(data, st->data == 1 ? "+OK\r\n" : "$-1\r\n", 5);
  } else if (st->data == 3) {
    int ret = bpf_skb_adjust_room(skb, 23 - len, 0, 0);
    if (ret < 0) {
      verbose("Failed to grow or shrink tail room by %d: %d.", 23 - len, ret);
      return SK_PASS;
    }

    ekcache_recompute_pkt_pointers(skb, &data, &data_end);
    if (data + 5 > data_end) return SK_PASS;
    __builtin_memcpy(data, "$16\r\n", 5);
    if (data + 5 + 18 > data_end) return SK_PASS;
    __builtin_memcpy(data + 5, defval, 18);
  }

  u64 idx = 0;
  verbose("skb stats: length = %d", skb->len);
  verbose("strp state: offset=%d accum_len=%d full_len=%d", BPF_CORE_READ(skb_cb, strp.strp.offset),
          BPF_CORE_READ(skb_cb, strp.accum_len), BPF_CORE_READ(skb_cb, strp.strp.full_len));
  int code = bpf_sk_redirect_hash(skb, &sockhash, &cookie, 0);
  verbose("Redirect return = %d (SK_PASS: %d, SK_DROP: %d)", code, SK_PASS, SK_DROP);

  return code;
}

SEC("sockops")
int ekcache_tcp_sockops(struct bpf_sock_ops *ctx) {
  int remote_port = bpf_ntohl(ctx->remote_port);
  int pid = bpf_get_current_task_btf()->tgid;
  int local_port = ctx->local_port;
  struct bpf_sock *sk = ctx->sk;
  int op = ctx->op;

  switch (op) {
    default:
      break;
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
      verbose("SOCKOP TCP_LISTEN: pid=%d local_port=%d remote_port=%d", pid, local_port, remote_port);
      break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
      verbose("SOCKOP PASSIVE_ESTABLISHED: pid=%d local_port=%d remote_port=%d", pid, local_port, remote_port);
      break;
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
      verbose("SOCKOP TCP_CONNECT: pid=%d local_port=%d remote_port=%d", pid, local_port, remote_port);
      break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
      verbose("SOCKOP ACTIVE_ESTABLISHED: pid=%d local_port=%d remote_port=%d", pid, local_port, remote_port);
      break;
  }

  if (local_port == ekcache_rx_dest_port && op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
    struct ekcache_sk_state *st, state = {};
    u64 cookie = bpf_get_socket_cookie(ctx);

    int ret = bpf_map_update_elem(&sk_hashmap, &cookie, &state, BPF_NOEXIST);
    if (ret < 0) {
      verbose("Failed to create state for socket cookie %lu: %d.", cookie, ret);
      return 0;
    }
    // Userspace fallback needs to use socket cookie identifier.
    ret = bpf_sock_hash_update(ctx, &sockhash, &cookie, 0);
    if (ret < 0) {
      verbose("Failed to add socket to SOCKHASH map: %d.", ret);
      bpf_map_delete_elem(&sk_hashmap, &cookie);
      return 0;
    }
    verbose("SOCKOP SOCK ADDED: pid=%d cookie=%d local_port=%d remote_port=%d sk_rcvbuf=%d.", pid, cookie, local_port,
            remote_port, BPF_CORE_READ((struct sk_buff *)ctx, sk, sk_rcvbuf));
  }

  return 1;
}

char _license[] SEC("license") = "GPL";
