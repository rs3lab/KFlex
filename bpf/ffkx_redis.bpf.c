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

ffkx_heap(256, 0) heap SEC(".maps");

// Heap

SEC("tc")
int ffkx_malloc_heap_base(struct __sk_buff *ctx) {
  void *map = &heap;
  ffkx_malloc_heap_kbase = ((struct bpf_map *)map)->kernel_base_addr;
  ffkx_malloc_heap_kmask = ((struct bpf_map *)map)->kernel_addr_mask;
  return 0;
}

struct ffkx_hashmap __hptr *ffkx_redis_hashmap;
struct ffkx_hashmap_bucket *ffkx_redis_hashmap_buckets;

uint64_t ffkx_redis_hashmap_key_size;
uint64_t ffkx_redis_hashmap_value_size;
uint64_t ffkx_redis_hashmap_max_entries_size;
uint64_t ffkx_redis_hashmap_nr_buckets;

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __type(key, __u64);
  __type(value, int);
  __uint(max_entries, 10000);
} sockhash SEC(".maps");

// Configuration options
// Destination port for Redis
const volatile int ffkx_redis_dest_port = 6969;

enum {
  // ZERO INIT should set to this value
  FFKX_PKT_STATE_READ_START = 0,
  FFKX_PKT_STATE_READ_CMD,
  FFKX_PKT_STATE_READ_SETK,
  FFKX_PKT_STATE_READ_KEY,
  FFKX_PKT_STATE_READ_VALUE,
};

enum {
  FFKX_PKT_CMD_UNKNOWN,
  FFKX_PKT_CMD_PING,
  FFKX_PKT_CMD_ZADD,
  FFKX_PKT_CMD_ZRANGBYLEX,
};

struct ffkx_pkt_state_machine {
  int type;
  int count;
  int cmd;
  int set_key_cnt;
  int key_cnt;
  int val_cnt;
  u32 hash;
  struct ffkx_skiplist_elem *sk_head;
};

#define FFKX_REDIS_KEY_BUF_SZ 512

void *ffkx_redis_key_buf;
void *ffkx_redis_value_buf;

static inline void *get_kv_buf(void *buf) { return buf + (bpf_get_smp_processor_id() * FFKX_REDIS_KEY_BUF_SZ); }

private(A) struct bpf_spin_lock lock;
/// Redis Skiplist Implementation
/// -- Skiplist -- ///

static __always_inline int ffkx_skiplist_cmp(void *node_key, u32 node_key_size, void *key, u32 key_size) {
  type_cast(void, node_key);
  key_size = node_key_size < key_size ? node_key_size : key_size;
  return bpf_ffkx_memcmp(ffkx_conv_hptr(node_key), ffkx_conv_hptr(key), key_size);
}

// FIXME: Use the same definitions in the kernel somehow, switch to a kernel
// module.
#define MAX_SKIPLIST_HEIGHT 32

struct ffkx_skiplist_elem {
  u32 height;
  u32 key_size;
  u32 value_size;
  struct ffkx_skiplist_elem *next[MAX_SKIPLIST_HEIGHT];
  char buf[];
};

// FIXME: Not multithreaded safe
struct ffkx_skiplist_elem **ffkx_skiplist_prev;

static __always_inline struct ffkx_skiplist_elem *ffkx_skiplist_elem_alloc(void *key, u32 key_size, void *value,
                                                                           u32 value_size) {
  struct ffkx_skiplist_elem *elem = ffkx_malloc(sizeof(*elem) + key_size + value_size);
  if (!elem) {
    return NULL;
  }
  cast(typeof(*elem), elem);
  // FIXME: make all of this less hairy: We must set key_size, as it used during comparison by kernel
  elem->key_size = key_size;
  elem->value_size = value_size;
  // FIXME: Memset fails, allow in verifier to do stores of 0 into any field.
  // __builtin_memset(elem, 0, sizeof(*elem))
  elem->height = (bpf_get_prandom_u32()) % MAX_SKIPLIST_HEIGHT;
  // Must be 1
  if (!elem->height) {
    elem->height++;
  }
  char *key_buf = elem->buf;
  ffkx_memcpy(ffkx_conv_hptr(key_buf), ffkx_conv_hptr(key), key_size);
  char *value_buf = elem->buf + key_size;
  ffkx_memcpy(ffkx_conv_hptr(value_buf), ffkx_conv_hptr(value), value_size);
  // Next pointers set after insertion
  return elem;
}

static __always_inline struct ffkx_skiplist_elem **ffkx_skiplist_nextp(struct ffkx_skiplist_elem *elem, int i) {
  auto ptr = &elem->next[i];
  cast(
      struct { struct ffkx_skiplist_elem *next; }, ptr);
  return ptr;
}

static __noinline int ffkx_skiplist_update(struct ffkx_skiplist_elem *head, void *key, u32 key_size, void *value,
                                           u32 value_size) {
  auto elem = ffkx_skiplist_elem_alloc(key, key_size, value, value_size);
  if (!elem) {
    return -ENOMEM;
  }
  struct ffkx_skiplist_elem **prev = ffkx_skiplist_prev;
  // Cast to void, as this is a buffer we will read/write values from/to
  // as scratch space
  cast(void, prev);
  struct ffkx_skiplist_elem *curr = head;
  int level = head->height - 1;
  scalar_cast(level);

  ffkx_while(curr && level >= 0) {
    prev[level] = curr;
    struct ffkx_skiplist_elem *ptr = *ffkx_skiplist_nextp(curr, level);
    if (ptr == NULL) {
      --level;
    } else {
      int cmp = ffkx_skiplist_cmp(ptr->buf, ptr->key_size, key, key_size);
      if (cmp == 0) {
        // FIXME: Simply coalesce
        return 0;
      } else if (cmp > 0) {
        --level;
      } else {
        curr = ptr;
      }
    }
    // FIXME: For convergence
    level = scalar_cast(level);
  }

  // Height key value already set for node
  for (int i = MAX_SKIPLIST_HEIGHT - 1; i > elem->height; cond_break, --i) {
    *ffkx_skiplist_nextp(elem, i) = NULL;
    // FIXME: For convergence
    i = scalar_cast(i);
  }

  for (int i = elem->height - 1; i >= 0; cond_break, --i) {
    // prev[i]
    auto pprev = prev + i;
    cast(void, pprev);
    auto prev_i = *pprev;
    cast(typeof(*prev_i), prev_i);
    // elem->next[i] = prev[i]->next[i];
    *ffkx_skiplist_nextp(elem, i) = *ffkx_skiplist_nextp(prev_i, i);
    // prev[i]->next[i] = elem;
    *ffkx_skiplist_nextp(prev_i, i) = elem;
    // FIXME: For convergence
    i = scalar_cast(i);
  }
  return 0;
}

static __noinline int ffkx_skiplist_lookup(struct ffkx_skiplist_elem *head, void *key, u32 key_size) {
  struct ffkx_skiplist_elem *curr = head;
  int level = head->height - 1;

  ffkx_while(curr && level >= 0) {
    struct ffkx_skiplist_elem *ptr = *ffkx_skiplist_nextp(curr, level);
    if (ptr == NULL) {
      level--;
    } else {
      int cmp = ffkx_skiplist_cmp(ptr->buf, ptr->key_size, key, key_size);
      if (cmp == 0) {
        return 0;
      } else if (cmp > 0) {
        level--;
      } else {
        curr = ptr;
      }
    }
    // FIXME: For convergence
    level = scalar_cast(level);
  }
  return -ENOENT;
}

static __noinline struct ffkx_skiplist_elem *ffkx_skiplist_alloc_head(void) {
  struct ffkx_skiplist_elem *elem = ffkx_malloc(sizeof(*elem));
  if (!elem) {
    return NULL;
  }
  cast(typeof(*elem), elem);
  // Initialize head
  elem->height = MAX_SKIPLIST_HEIGHT;
  return elem;
}

// INIT
SEC("tc")
int ffkx_redis_hashmap_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);

  // Allocated by userspace
  auto map = ffkx_redis_hashmap;
  auto buckets = ffkx_redis_hashmap_buckets;

  ffkx_hashmap_init_key_size = ffkx_redis_hashmap_key_size;
  ffkx_hashmap_init_value_size = ffkx_redis_hashmap_value_size;
  ffkx_hashmap_init_max_entries = ffkx_redis_hashmap_max_entries_size;

  if (!ffkx_redis_hashmap_nr_buckets) {
    return ENOMEM;
  }
  // Initialize
  if (!ffkx_skiplist_prev) {
    return ENOMEM;
  }
  return ffkx_hashmap_init(map, buckets, ffkx_redis_hashmap_nr_buckets);
}

/// Redis sorted set functions

static __noinline int ffkx_redis_create_sorted_set(void *key, u32 key_size, u32 hash,
                                                   struct ffkx_pkt_state_machine *sm) {
  // Value is the pointer to be stored.
  struct ffkx_skiplist_elem **value = ffkx_hashmap_lookup_redis(ffkx_redis_hashmap, key, key_size, hash);
  if (!value) {
    ffkx_log_debug("Failed value lookup, allocating head");
    auto skiplist = ffkx_skiplist_alloc_head();
    if (!skiplist) {
      ffkx_log_error("Allocation of skiplist head failed.");
      return -ENOMEM;
    }
    // FIXME:
    int ret = ffkx_hashmap_update_redis(ffkx_redis_hashmap, key, key_size, &skiplist, sizeof(skiplist), hash);
    if (ret < 0) {
      ffkx_log_error("Failed to perform hashmap update: ret=%d", ret);
      return ret;
    }
    ffkx_log_debug("Created new entry for sorted set");
    sm->sk_head = skiplist;
    return 0;
  }
  // Get the value into sm->sk_head, don't care about translation stuff
  cast(void, value);
  sm->sk_head = *value;
  ffkx_log_debug("Looked up entry for sorted set, stored");
  // Load pointer from value
  return 0;
}

/// Packet state machine functions

// We reach here at start of packet, we read until we see the second '\n'.
int __noinline ffkx_redis_pkt_read_start(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  if (c != '\n') {
    return FFKX_PKT_READ_CONT;
  }
  // Update '\n' count.
  sm->count++;
  // Did we encounter the second '\n'?
  if (sm->count == 2) {
    // Skipped over first 2 elements to start reading the command.
    sm->type = FFKX_PKT_STATE_READ_CMD;
    sm->count = 0;
  }
  return FFKX_PKT_READ_CONT;
}

// We reach here at start of the command, read until '\n'.
int __noinline ffkx_redis_pkt_read_cmd(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  if (!sm->count) {
    if (c == 'p' || c == 'P') {
      ffkx_log_debug("Detected command=ping");
      sm->cmd = FFKX_PKT_CMD_PING;
      sm->count = 0;
      return FFKX_PKT_READ_DONE;
    } else if (c != 'z' && c != 'Z') {
      return -EINVAL;
    }
    sm->count = 1;
    ffkx_log_debug("Detected first byte Z");
    return FFKX_PKT_READ_CONT;
  } else if (sm->count == 1) {
    if (c == 'a' || c == 'A') {
      sm->cmd = FFKX_PKT_CMD_ZADD;
      // Let's enter branches below now
      sm->count++;
      return FFKX_PKT_READ_CONT;
    } else if (c == 'r' || c == 'R') {
      sm->cmd = FFKX_PKT_CMD_ZRANGBYLEX;
      // Let's enter branches below now
      sm->count++;
      return FFKX_PKT_READ_CONT;
    } else {
      ffkx_log_error("Unknown command");
      return -EFAULT;
    }
  } else if (c == '\n') {
    // Reached end of command, now start of key length
    ffkx_log_debug("Detected command=%s", sm->cmd == FFKX_PKT_CMD_ZADD ? "zadd" : "zrangebylex");
    sm->type = FFKX_PKT_STATE_READ_SETK;
    sm->count = 0;
    return FFKX_PKT_READ_CONT;
  } else {
    // Keep going
    return FFKX_PKT_READ_CONT;
  }
  ffkx_log_error("Unreachable condition for cmd sm->count=%d", sm->count);
  return -EINVAL;
}

// We reach here at start of sorted set key length, we end at '\n' of set key.
int __noinline ffkx_redis_pkt_read_setk(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  ffkx_log_debug("setk sm->count=%d", sm->count);
  // We have not seen set key length.
  if (!sm->count) {
    // Continue until we see end of key length.
    if (c != '\n') {
      ffkx_log_debug("skip keylen char, sm->count=%d", sm->count);
      return FFKX_PKT_READ_CONT;
    }
    // We saw '\n', let's switch to count = 1 (means we process the sorted set
    // key now).
    sm->count = 1;
    ffkx_log_debug("setk saw newline, sm->count=%d", sm->count);
    return FFKX_PKT_READ_CONT;
  } else if (sm->count == 1) {
    if (c == '\r') {
      // We finished processing the sorted set key. Let's make it known.
      ffkx_log_debug("sset key len=%d", sm->set_key_cnt);
      return FFKX_PKT_READ_CONT;
    } else if (c == '\n') {
      // Done, switch state machine mode.
      sm->type = FFKX_PKT_STATE_READ_KEY;
      sm->count = 0;
      ffkx_log_debug("sset key newline");

      // Now, we create the sorted set in hashmap if not created already.
      auto key = get_kv_buf(ffkx_redis_key_buf);
      cast(void, key);
      // This function creates or finds skiplist head for the current set in
      // sm->sk_head.
      bpf_spin_lock(&lock);
      int ret = ffkx_redis_create_sorted_set(key, sm->set_key_cnt, sm->hash, sm);
      if (ret < 0) {
        ffkx_log_debug("Failed to create sorted set for key ret=%d", ret);
	bpf_spin_unlock(&lock);
	return ret;
      }
      bpf_spin_unlock(&lock);
      return FFKX_PKT_READ_CONT;
    } else {
      if (sm->set_key_cnt == FFKX_REDIS_KEY_BUF_SZ) {
        ffkx_log_error("Key size bigger than buf size %d", FFKX_REDIS_KEY_BUF_SZ);
        return -EFAULT;
      } else if (!sm->set_key_cnt) {
        // FIXME: Not needed, but let's add it here until deadline.
        sm->hash = FNV_OFFSET_BASIS_32;
      }
      // Record key
      char *buf = get_kv_buf(ffkx_redis_key_buf);
      buf += sm->set_key_cnt;
      cast(void, buf);
      // Byte in sset key
      *buf = c;
      sm->set_key_cnt++;
      ffkx_log_debug("key=%c", c);
      sm->hash ^= c;
      sm->hash *= FNV_PRIME_32;
      return FFKX_PKT_READ_CONT;
    }
  }
  // Can't reach here
  ffkx_log_error("Error, not handled sm->count=%d", sm->count);
  return -EINVAL;
}

int __noinline ffkx_redis_pkt_read_key(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  // We can use key_buf and key_cnt to count
  // We store from start until second '\n'
  // sm->count == 0 means we haven't seen first '\n'
  if (!sm->count) {
    // Store char
    char *key = get_kv_buf(ffkx_redis_key_buf) + sm->key_cnt;
    cast(void, key);
    *key = c;
    sm->key_cnt++;
    ffkx_log_debug("key=%c cnt=%d", c, sm->key_cnt);
    // seen first '\n'
    if (c == '\n') {
      sm->count = 1;
      ffkx_log_debug("Read size, reading more");
    }
    return FFKX_PKT_READ_CONT;
  } else if (sm->count == 1) {
    char *key = get_kv_buf(ffkx_redis_key_buf) + sm->key_cnt;
    cast(void, key);
    *key = c;
    sm->key_cnt++;
    ffkx_log_debug("key=%c cnt=%d", c, sm->key_cnt);
    // Second n, switch to value
    if (c == '\n') {
      sm->type = FFKX_PKT_STATE_READ_VALUE;
      sm->count = 0;
    }
    return FFKX_PKT_READ_CONT;
  }
  ffkx_log_error("Unimplemented rkey");
  return -EINVAL;
}

int __noinline ffkx_redis_pkt_read_value(char c, struct ffkx_pkt_state_machine *sm) {
  if (!sm) {
    return -EBADF;
  }
  if (!sm->count) {
    if (!sm->key_cnt) {
      ffkx_log_error("Bad state machine zero key_cnt=0");
      return -EFAULT;
    }
    // Copy to val buffer
    char *val = get_kv_buf(ffkx_redis_value_buf) + sm->val_cnt;
    cast(void, val);
    *val = c;
    sm->val_cnt++;
    ffkx_log_debug("val=%c cnt=%d", c, sm->val_cnt);
    if (c == '\n') {
      sm->count = 1;
      ffkx_log_debug("read value len, read more");
    }
    return FFKX_PKT_READ_CONT;
  } else if (sm->count == 1) {
    // Copy to val buffer
    char *val = get_kv_buf(ffkx_redis_value_buf) + sm->val_cnt;
    cast(void, val);
    *val = c;
    sm->val_cnt++;
    ffkx_log_debug("val=%c cnt=%d", c, sm->val_cnt);
    // Got one key and value
    if (c == '\n') {
      auto ks = sm->key_cnt;
      auto vs = sm->val_cnt;
      // Reset transient state.
      sm->key_cnt = 0;
      sm->val_cnt = 0;
      sm->count = 0;
      // Read another key
      sm->type = FFKX_PKT_STATE_READ_KEY;

      bpf_spin_lock(&lock);
      // Now push to skiplist
      struct ffkx_skiplist_elem *head = sm->sk_head;
      cast(typeof(*head), head);
      // FIXME: ffkx_skiplist_update expects proper formed pointers
      int ret = ffkx_skiplist_update(head, ffkx_conv_hptr(get_kv_buf(ffkx_redis_key_buf)), ks,
                                     ffkx_conv_hptr(get_kv_buf(ffkx_redis_value_buf)), vs);
      if (ret < 0) {
        ffkx_log_error("Failed to perform skiplist update ret=%d", ret);
	bpf_spin_unlock(&lock);
	return ret;
      }
      bpf_spin_unlock(&lock);
      ffkx_log_debug("Added element to skiplist");
      ffkx_log_debug("Validation=%d", ffkx_skiplist_lookup(head, ffkx_conv_hptr(get_kv_buf(ffkx_redis_key_buf)), ks));
      // If no more key/values, don't complain
      return FFKX_PKT_READ_BNDR;
    } else {
      // Just more bytes, keep accumulating
      return FFKX_PKT_READ_CONT;
    }
  }
  ffkx_log_error("Unimplemented value");
  return -EINVAL;
}

static __noinline int ffkx_redis_pkt_read(char *buf, const int size, u32 *offp, void *userdata) {
  struct ffkx_pkt_state_machine *sm = userdata;
  int ret;

  int i;
  bpf_for(i, 0, size) {
    ++*offp;
    switch (sm->type) {
      case FFKX_PKT_STATE_READ_START:
        ret = ffkx_redis_pkt_read_start(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      case FFKX_PKT_STATE_READ_CMD:
        ret = ffkx_redis_pkt_read_cmd(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      case FFKX_PKT_STATE_READ_SETK:
        ret = ffkx_redis_pkt_read_setk(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      case FFKX_PKT_STATE_READ_KEY:
        ret = ffkx_redis_pkt_read_key(buf[i], sm);
        if (ret) {
          return ret;
        }
        break;
      case FFKX_PKT_STATE_READ_VALUE:
        ret = ffkx_redis_pkt_read_value(buf[i], sm);
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
  int write_ping;
  int write_somefin;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct action_write);
  __uint(max_entries, 1);
} action SEC(".maps");

SEC("sk_skb/stream_parser")
int ffkx_redis_rx_stream_parser(struct __sk_buff *skb) {
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

  // Execution of Redis prog is single threaded
  ret = -EFAULT;
  struct ffkx_pkt_state_machine sm = {0};
  ffkx_pkt_read_loop(&dptr, &off, &ret, ffkx_redis_pkt_read, &sm);
  // Execution of Redis prog is single threaded
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
    case FFKX_PKT_CMD_PING:
      w->write_ping = 1;
      break;
    case FFKX_PKT_CMD_ZADD:
    case FFKX_PKT_CMD_ZRANGBYLEX:
      w->write_somefin = 1;
      break;
    default:
      ffkx_pkt_log_error(skb, "Unknown pkt command");
      // FIXME: We have a bug, where write_somefin is not set in some cases (packet
      // processed but cmd not assigned for some reason), let's debug after
      // deadline.
      w->write_somefin = 1;
      break;
  }
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int ffkx_redis_rx_stream_verdict(struct __sk_buff *skb) {
  struct sk_skb_cb *skb_cb = (void *)((struct sk_buff *)skb)->cb;

  u64 cookie = bpf_get_socket_cookie(skb);
  u32 off = BPF_CORE_READ(skb_cb, strp.strp.offset);
  int ret;
  struct action_write *w = bpf_map_lookup_elem(&action, &(int){0});
  if (!w) {
    ffkx_pkt_log_error(skb, "Failed to do percpu map lookup");
    return skb->len;
  }
  if (w->write_ping) {
    w->write_ping = 0;
    ret = bpf_skb_adjust_room(skb, 7 - skb->len, 0, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_adjust_room 7");
      return SK_PASS;
    }
    ret = bpf_skb_store_bytes(skb, off, "+PONG\r\n", 7, 0);
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
  } else if (w->write_somefin) {
    w->write_somefin = 0;
    ffkx_log_debug("We processed a ZADD query, let's generate a response");
    ret = bpf_skb_adjust_room(skb, 4 - skb->len, 0, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_adjust_room 4");
      return SK_PASS;
    }
    ret = bpf_skb_store_bytes(skb, off, ":1\r\n", 4, 0);
    if (ret < 0) {
      ffkx_pkt_log_error(skb, "Failed to skb_store_bytes 4");
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
int ffkx_redis_sockops(struct bpf_sock_ops *ctx) {
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

  if (lport == ffkx_redis_dest_port && op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
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
