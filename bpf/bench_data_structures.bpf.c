// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <ffkx_hashmap.bpf.h>
#include <ffkx_heap.bpf.h>
#include <ffkx_list.bpf.h>
#include <ffkx_log.bpf.h>
#include <ffkx_malloc.bpf.h>
#include <ffkx_rbtree.bpf.h>
#include <ffkx_sketch.bpf.h>
#include <ffkx_util.bpf.h>

ffkx_heap(64, 0) heap SEC(".maps");

/// --- Data Structures Benchmarks --- ///

// Parameters
const volatile uint64_t bench_data_structures_key_size;
const volatile uint64_t bench_data_structures_value_size;
const volatile uint64_t bench_data_structures_max_entries;
const volatile bool bench_data_structures_multithreaded;

// Counters
uint64_t bench_data_structures_iterations;

// FIXME: deletes in multithreaded mode
uint64_t bench_data_structures_deletes;

#define BENCH_SINGLE_THREAD(ret) (bench_data_structures_multithreaded ? 0 : ret)

#define BENCH_REGISTER(expr)                                                                              \
  SEC("tc")                                                                                               \
  int bench_##expr(struct __sk_buff *ctx) {                                                               \
    void *data_end = (void *)(long)ctx->data_end;                                                         \
    void *data = (void *)(long)ctx->data;                                                                 \
    void *value, *key;                                                                                    \
    int ret = TC_ACT_OK;                                                                                  \
                                                                                                          \
    if (data + bench_data_structures_key_size + bench_data_structures_value_size > data_end) {            \
      ret = 1024;                                                                                         \
      goto end;                                                                                           \
    }                                                                                                     \
    key = data;                                                                                           \
    value = data + bench_data_structures_key_size;                                                        \
    u64 begin_time = bpf_ktime_get_ns();                                                                  \
    ret = bench_def_##expr(key, bench_data_structures_key_size, value, bench_data_structures_value_size); \
    *(u64 *)data = bpf_ktime_get_ns() - begin_time;                                                       \
    __sync_fetch_and_add(&bench_data_structures_iterations, 1);                                           \
  end:                                                                                                    \
    return ret;                                                                                           \
  }

#define BENCH_DEFINE(name) \
  static __always_inline int bench_def_##name(void *key, u64 key_size, void *value, u64 value_size)

// Heap

SEC("tc")
int ffkx_malloc_heap_base(struct __sk_buff *ctx) {
  void *map = &heap;
  ffkx_malloc_heap_kbase = ((struct bpf_map *)map)->kernel_base_addr;
  ffkx_malloc_heap_kmask = ((struct bpf_map *)map)->kernel_addr_mask;
  return 0;
}

/// --- Linked List --- ///

// FIXME: Use separate types without owner similar to RBTree for linked list as
// well.

struct ffkx_linked_list_elem {
  struct list_head node;
  u64 owner;
  char buf[];
};

// Not marked as hptr, as kernel uses same pointer for benchmarking
struct list_head *bench_linked_list_ffkx;
bool bench_linked_list_ffkx_mode;

static __always_inline void ffkx_linked_list_init(struct list_head *head) {
  // For FFKX mode, we compare off == off, hence store off as well
  // Otherwise, head won't compare equal.
  if (bench_linked_list_ffkx_mode) {
    head->next = head;
    head->prev = head;
  } else {
    // FIXME: should be possible to drop, as RHS is not ptr
    cast(void, head);
    head->next = ffkx_conv_hptr(head);
    head->prev = ffkx_conv_hptr(head);
    cast(typeof(*head), head);
  }
}

static __always_inline struct ffkx_linked_list_elem *ffkx_linked_list_alloc(void *key, u32 key_size, void *value,
                                                                            u32 value_size) {
  struct ffkx_linked_list_elem *elem = ffkx_malloc(sizeof(*elem) + key_size + value_size);
  if (!elem) {
    return NULL;
  }
  cast(typeof(*elem), elem);
  __builtin_memset(elem, 0, sizeof(*elem));
  ffkx_linked_list_init(&elem->node);

  if (!key_size && !value_size) {
    return elem;
  }
  if (!key_size || !value_size) {
    ffkx_log_error("Invalid values passed to alloc function");
    return NULL;
  }
  char *key_buf = elem->buf;
  ffkx_memcpy(ffkx_conv_hptr(key_buf), key, key_size);
  char *value_buf = elem->buf + key_size;
  ffkx_memcpy(ffkx_conv_hptr(value_buf), value, value_size);
  return elem;
}

SEC("tc")
int bench_linked_list_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);
  // Use elem for head pointer, as we also need owner field here.
  struct list_head *head = (struct list_head *)ffkx_linked_list_alloc(NULL, 0, NULL, 0);
  if (!head) {
    return ENOMEM;
  }
  // Store the complete value in pointer, as it is the same value used for
  // non-FFKX kfuncs as well, which expect a fully formed pointer.
  bench_linked_list_ffkx = ffkx_conv_hptr(head);
  cast(typeof(*head), head);
  ffkx_linked_list_init(head);
  return 0;
}

BENCH_DEFINE(ffkx_linked_list_update) {
  bpf_register_heap(&heap);
  struct ffkx_linked_list_elem *elem = ffkx_linked_list_alloc(key, key_size, value, value_size);
  if (!elem) {
    return ENOMEM;
  }
  auto head = bench_linked_list_ffkx;
  cast(typeof(*head), head);

  list_add(&elem->node, head);
  return 0;
}

BENCH_DEFINE(ffkx_linked_list_lookup) {
  bpf_register_heap(&heap);
  struct ffkx_linked_list_elem *elem, *n;

  auto *head = bench_linked_list_ffkx;
  cast(typeof(*head), head);

  int cnt = 0;
  list_for_each_entry_safe(elem, n, head, node) {
    cnt++;
    char *key_buf = elem->buf;
    if (ffkx_memequal(ffkx_conv_hptr(key_buf), key, key_size)) {
      return 0;
    }
  }
  return ENOENT;
}

BENCH_DEFINE(ffkx_linked_list_delete) {
  bpf_register_heap(&heap);
  struct ffkx_linked_list_elem *elem, *n;

  auto *head = bench_linked_list_ffkx;
  cast(typeof(*head), head);

  list_for_each_entry_safe(elem, n, head, node) {
    char *key_buf = elem->buf;
    if (ffkx_memequal(ffkx_conv_hptr(key_buf), key, key_size)) {
      list_del(&elem->node);
      ffkx_free(elem);
      return 0;
    }
  }
  return ENOENT;
}

BENCH_REGISTER(ffkx_linked_list_update);
BENCH_REGISTER(ffkx_linked_list_lookup);
BENCH_REGISTER(ffkx_linked_list_delete);

// BPF Linked List

int bpf_bench_linked_list_update(struct ffkx_linked_list_elem *elem, struct list_head *head, void *key, void *value,
                                 u64 key_value_size) __ksym;

BENCH_DEFINE(bpf_linked_list_update) {
  bpf_register_heap(&heap);
  struct ffkx_linked_list_elem *elem = ffkx_linked_list_alloc(key, key_size, value, value_size);
  if (!elem) {
    return ENOMEM;
  }
  return bpf_bench_linked_list_update(ffkx_conv_hptr(elem), bench_linked_list_ffkx, key, value,
                                      (((u64)key_size) << 32) | ((u64)value_size));
}

int bpf_bench_linked_list_lookup(struct list_head *head, void *key, u32 key_size) __ksym;

BENCH_DEFINE(bpf_linked_list_lookup) { return bpf_bench_linked_list_lookup(bench_linked_list_ffkx, key, key_size); }

int bpf_bench_linked_list_delete(struct list_head *head, void *key, u32 key_size) __ksym;

BENCH_DEFINE(bpf_linked_list_delete) { return bpf_bench_linked_list_delete(bench_linked_list_ffkx, key, key_size); }

BENCH_REGISTER(bpf_linked_list_update);
BENCH_REGISTER(bpf_linked_list_lookup);
BENCH_REGISTER(bpf_linked_list_delete);

// BPF Graph Linked List

int bpf_bench_graph_linked_list_update(struct ffkx_linked_list_elem *elem, struct list_head *head, void *key,
                                       void *value, u64 key_value_size) __ksym;

BENCH_DEFINE(bpf_graph_linked_list_update) {
  bpf_register_heap(&heap);
  struct ffkx_linked_list_elem *elem = ffkx_malloc(sizeof(*elem) + key_size + value_size);
  if (!elem) {
    return ENOMEM;
  }
  cast(typeof(*elem), elem);
  return bpf_bench_graph_linked_list_update(ffkx_conv_hptr(elem), bench_linked_list_ffkx, key, value,
                                            (((u64)key_size) << 32) | ((u64)value_size));
}

int bpf_bench_graph_linked_list_lookup(struct list_head *head, void *key, u32 key_size) __ksym;

BENCH_DEFINE(bpf_graph_linked_list_lookup) {
  return bpf_bench_graph_linked_list_lookup(bench_linked_list_ffkx, key, key_size);
}

int bpf_bench_graph_linked_list_delete(struct list_head *head, void *key, u32 key_size) __ksym;

BENCH_DEFINE(bpf_graph_linked_list_delete) {
  return bpf_bench_graph_linked_list_delete(bench_linked_list_ffkx, key, key_size);
}

BENCH_REGISTER(bpf_graph_linked_list_update);
BENCH_REGISTER(bpf_graph_linked_list_lookup);
BENCH_REGISTER(bpf_graph_linked_list_delete);

/// --- RB Tree --- ///

struct ffkx_rbtree_elem {
  struct ffkx_rb_node node;
  char buf[];
};

struct rb_root_cached ffkx_bpf_rb_root;
struct ffkx_rb_root_cached __hptr *ffkx_rb_root;

SEC("tc")
int bench_rbtree_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);
  // Initialize
  if (!ffkx_rb_root) {
    return ENOMEM;
  }
  auto root = ffkx_rb_root;
  // FIXME: Use macro RB_ROOT_CACHED
  root->rb_root.rb_node = NULL;
  root->rb_leftmost = NULL;
  return 0;
}

static __always_inline struct ffkx_rbtree_elem *ffkx_rbtree_alloc(void *key, u32 key_size, void *value, u32 value_size,
                                                                  bool kernel) {
  struct ffkx_rbtree_elem *elem = ffkx_malloc(sizeof(*elem) + key_size + value_size);
  if (!elem) {
    return NULL;
  }
  cast(typeof(*elem), elem);
  __builtin_memset(elem, 0, sizeof(*elem));
  // FIXME: Replace with RB_CLEAR_NODE
  // We need to store actual value for kernel mode, and offset for our case.
  if (kernel) {
    // FIXME: RB_CLEAR_NODE done by kernel
    elem->node.__rb_parent_color = 0;
  } else {
    RB_CLEAR_NODE(&elem->node);
  }
  char *key_buf = elem->buf;
  ffkx_memcpy(ffkx_conv_hptr(key_buf), key, key_size);
  char *value_buf = elem->buf + key_size;
  ffkx_memcpy(ffkx_conv_hptr(value_buf), value, value_size);
  return elem;
}

int bpf_bench_rbtree_update(struct rb_root_cached *root, struct rb_node *node, u32 key_size) __ksym;

BENCH_DEFINE(bpf_rbtree_update) {
  bpf_register_heap(&heap);
  struct ffkx_rbtree_elem *elem = ffkx_rbtree_alloc(key, key_size, value, value_size, true);
  if (!elem) {
    return ENOMEM;
  }
  return bpf_bench_rbtree_update(&ffkx_bpf_rb_root, ffkx_conv_hptr(&elem->node), key_size);
}

u64 bpf_bench_rbtree_lookup(struct rb_root_cached *root__ign, void *key__ign, u32 key_size) __ksym;

BENCH_DEFINE(bpf_rbtree_lookup) {
  bpf_register_heap(&heap);
  return bpf_bench_rbtree_lookup(&ffkx_bpf_rb_root, key, key_size) == ENOENT ? ENOENT : 0;
}

int bpf_bench_rbtree_delete(struct rb_root_cached *root, void *key, u32 key_size) __ksym;

BENCH_DEFINE(bpf_rbtree_delete) {
  bpf_register_heap(&heap);
  return bpf_bench_rbtree_delete(&ffkx_bpf_rb_root, key, key_size);
}

BENCH_REGISTER(bpf_rbtree_update);
BENCH_REGISTER(bpf_rbtree_lookup);
BENCH_REGISTER(bpf_rbtree_delete);

// FFKX RBTree

static __always_inline int bpf_bench_rbtree_cmp(struct ffkx_rb_node *node, struct ffkx_rb_node *parent, u32 key_size) {
  // We want the less operator to be dependent on input size in terms of
  // complexity. Let's memequal before we return a result.
  void *node_key1 = (node + 1), *node_key2 = (parent + 1);
  type_cast(void, node_key1);
  type_cast(void, node_key2);
  bool equal = ffkx_memequal(ffkx_conv_hptr(node_key1), ffkx_conv_hptr(node_key2), key_size);
  bool less = (*(u64 *)node_key1) < (*(u64 *)node_key2);
  return equal ? 0 : (less ? -1 : 1);
}

static __always_inline int bpf_bench_rbtree_key_cmp(void *key, struct ffkx_rb_node *node, u32 key_size) {
  // FIXME: Put in rbtree header
  _Static_assert(sizeof(*ffkx_rb_root) == sizeof(struct rb_root_cached), "");
  _Static_assert(sizeof(*node) == sizeof(struct rb_node), "");
  // We want the less operator to be dependent on input size in terms of
  // complexity. Let's memequal before we return a result.
  void *node_key1 = key, *node_key2 = (node + 1);
  type_cast(void, node_key2);
  bool equal = ffkx_memequal(node_key1, ffkx_conv_hptr(node_key2), key_size);
  bool less = (*(u64 *)node_key1) < (*(u64 *)node_key2);
  return equal ? 0 : (less ? -1 : 1);
}

BENCH_DEFINE(ffkx_rbtree_update) {
  // FIXME: Let's eliminate this kludge
  bpf_register_heap(&heap);

  struct ffkx_rbtree_elem *elem = ffkx_rbtree_alloc(key, key_size, value, value_size, false);
  if (!elem) {
    return ENOMEM;
  }

  struct ffkx_rb_node **link = &ffkx_rb_root->rb_root.rb_node;
  struct ffkx_rb_node *parent = NULL, *n = &elem->node;
  bool leftmost = true;

  RB_CLEAR_NODE(n);

  ffkx_while(*link) {
    parent = *link;
    if (bpf_bench_rbtree_cmp(n, parent, key_size) < 0) {
      link = &parent->rb_left;
    } else {
      link = &parent->rb_right;
      leftmost = false;
    }
  }

  rb_link_node(n, parent, link);
  rb_insert_color_cached(n, ffkx_rb_root, leftmost);
  return 0;
}

BENCH_DEFINE(ffkx_rbtree_lookup) {
  bpf_register_heap(&heap);
  struct ffkx_rb_node *node = ffkx_rb_root->rb_root.rb_node;

  ffkx_while(node) {
    int cmp = bpf_bench_rbtree_key_cmp(key, node, key_size);

    if (cmp < 0)  // less
      node = node->rb_left;
    else if (cmp > 0)  // greater
      node = node->rb_right;
    else  // equal
      return 0;
  }
  return ENOENT;
}

BENCH_DEFINE(ffkx_rbtree_delete) {
  bpf_register_heap(&heap);
  struct ffkx_rb_node *node = ffkx_rb_root->rb_root.rb_node;

  ffkx_while(node) {
    int cmp = bpf_bench_rbtree_key_cmp(key, node, key_size);

    if (cmp < 0)  // less
      node = node->rb_left;
    else if (cmp > 0)  // greater
      node = node->rb_right;
    else {  // equal
      rb_erase_cached(node, ffkx_rb_root);
      RB_CLEAR_NODE(node);
      return 0;
    }
  }
  return ENOENT;
}

BENCH_REGISTER(ffkx_rbtree_update);
BENCH_REGISTER(ffkx_rbtree_lookup);
BENCH_REGISTER(ffkx_rbtree_delete);

/// --- Hash Table --- ///

// FFKX Hashmap

struct ffkx_hashmap __hptr *bench_hashmap_ffkx;
struct ffkx_hashmap_bucket __hptr *bench_ffkx_hashmap_buckets;
uint64_t bench_ffkx_hashmap_nr_buckets;

SEC("tc")
int bench_ffkx_hashmap_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);

  // Allocated by userspace
  auto map = bench_hashmap_ffkx;
  auto buckets = bench_ffkx_hashmap_buckets;

  ffkx_hashmap_init_key_size = bench_data_structures_key_size;
  ffkx_hashmap_init_value_size = bench_data_structures_value_size;
  ffkx_hashmap_init_max_entries = bench_data_structures_max_entries;

  if (!bench_ffkx_hashmap_nr_buckets) {
    return ENOMEM;
  }
  return ffkx_hashmap_init(map, buckets, bench_ffkx_hashmap_nr_buckets);
}

BENCH_DEFINE(ffkx_hashmap_update) {
  bpf_register_heap(&heap);
  int ret = ffkx_hashmap_update(bench_hashmap_ffkx, key, key_size, value, value_size);
  if (ret) {
    return -ret;
  }
  return 0;
}

BENCH_DEFINE(ffkx_hashmap_lookup) {
  bpf_register_heap(&heap);
  void *ret = ffkx_hashmap_lookup(bench_hashmap_ffkx, key, key_size);
  if (!ret) {
    return ENOENT;
  }
  return 0;
}

BENCH_DEFINE(ffkx_hashmap_delete) {
  bpf_register_heap(&heap);
  if (!ffkx_hashmap_delete(bench_hashmap_ffkx, key, key_size)) bench_data_structures_deletes++;
  return 0;
}
/*
BENCH_DEFINE(ffkx_hashmap_stress) {
  bpf_register_heap(&heap);
  int err = ffkx_hashmap_update(bench_hashmap_ffkx, key, key_size, value, value_size);
  if (err) {
    return -err;
  }
  if (!ffkx_hashmap_lookup(bench_hashmap_ffkx, key, key_size)) {
    // Ignore errors if multithreaded
    return BENCH_SINGLE_THREAD(ENOENT);
  }
  err = ffkx_hashmap_delete(bench_hashmap_ffkx, key, key_size);
  if (err) {
    // Ignore errors if multithreaded
    return BENCH_SINGLE_THREAD(-err);
  }
  bench_data_structures_deletes++;
  return 0;
}
*/
BENCH_REGISTER(ffkx_hashmap_update);
BENCH_REGISTER(ffkx_hashmap_lookup);
BENCH_REGISTER(ffkx_hashmap_delete);
//BENCH_REGISTER(ffkx_hashmap_stress);

// BPF Hashmap

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, 4);
  __uint(value_size, 4);
  __uint(max_entries, 1);
} bench_hashmap_prealloc SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, 4);
  __uint(value_size, 4);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} bench_hashmap SEC(".maps");

BENCH_DEFINE(bpf_hashmap_update) {
  int err = bpf_map_update_elem(&bench_hashmap_prealloc, key, value, 0);
  if (err) {
    return -err;
  }
  return 0;
}

BENCH_DEFINE(bpf_hashmap_lookup) {
  if (!bpf_map_lookup_elem(&bench_hashmap_prealloc, key)) {
    return ENOENT;
  }
  return 0;
}

BENCH_DEFINE(bpf_hashmap_delete) {
  if (!bpf_map_delete_elem(&bench_hashmap_prealloc, key)) bench_data_structures_deletes++;
  return 0;
}

BENCH_DEFINE(bpf_hashmap_stress) {
  int flags = bench_data_structures_multithreaded ? 0 : BPF_NOEXIST;
  int err = bpf_map_update_elem(&bench_hashmap_prealloc, key, value, flags);
  if (err) {
    return -err;
  }
  if (!bpf_map_lookup_elem(&bench_hashmap_prealloc, key)) {
    // Ignore errors if multithreaded
    return BENCH_SINGLE_THREAD(ENOENT);
  }
  err = bpf_map_delete_elem(&bench_hashmap_prealloc, key);
  if (err) {
    // Ignore errors if multithreaded
    return BENCH_SINGLE_THREAD(-err);
  }
  bench_data_structures_deletes++;
  return 0;
}

BENCH_REGISTER(bpf_hashmap_update);
BENCH_REGISTER(bpf_hashmap_lookup);
BENCH_REGISTER(bpf_hashmap_delete);
BENCH_REGISTER(bpf_hashmap_stress);

/// -- Skiplist -- ///

static __always_inline int bpf_bench_skiplist_cmp(void *node_key, void *key, u32 key_size) {
  type_cast(void, node_key);
  bool equal = ffkx_memequal(ffkx_conv_hptr(node_key), key, key_size);
  bool less = (*(u64 *)node_key) < (*(u64 *)key);
  return equal ? 0 : (less ? -1 : 1);
}

// FIXME: Use the same definitions in the kernel somehow, switch to a kernel
// module.
#define MAX_SKIPLIST_HEIGHT 32

struct ffkx_skiplist_elem {
  u32 height;
  u32 key_size;
  struct ffkx_skiplist_elem *next[MAX_SKIPLIST_HEIGHT];
  char buf[];
};

struct ffkx_skiplist_elem __hptr *ffkx_skiplist_head;
// FIXME: Not multithreaded safe
struct ffkx_skiplist_elem **ffkx_skiplist_prev;

SEC("tc")
int bench_skiplist_init(struct __sk_buff *ctx) {
  bpf_register_heap(&heap);
  // Initialize
  if (!ffkx_skiplist_head || !ffkx_skiplist_prev) {
    return ENOMEM;
  }
  ffkx_skiplist_head->height = MAX_SKIPLIST_HEIGHT;
  return 0;
}

static __always_inline struct ffkx_skiplist_elem *ffkx_skiplist_elem_alloc(void *key, u32 key_size, void *value,
                                                                           u32 value_size) {
  struct ffkx_skiplist_elem *elem = ffkx_malloc(sizeof(*elem) + key_size + value_size);
  if (!elem) {
    return NULL;
  }
  cast(typeof(*elem), elem);
  // FIXME: make all of this less hairy: We must set key_size, as it used during comparison by kernel
  elem->key_size = key_size;
  // FIXME: Memset fails, allow in verifier to do stores of 0 into any field.
  // __builtin_memset(elem, 0, sizeof(*elem))
  elem->height = (bpf_get_prandom_u32()) % MAX_SKIPLIST_HEIGHT;
  // Must be 1
  if (!elem->height) {
    elem->height++;
  }
  char *key_buf = elem->buf;
  ffkx_memcpy(ffkx_conv_hptr(key_buf), key, key_size);
  char *value_buf = elem->buf + key_size;
  ffkx_memcpy(ffkx_conv_hptr(value_buf), value, value_size);
  // Next pointers set after insertion
  return elem;
}

static __always_inline struct ffkx_skiplist_elem **ffkx_skiplist_nextp(struct ffkx_skiplist_elem *elem, int i) {
  auto ptr = &elem->next[i];
  cast(
      struct { struct ffkx_skiplist_elem *next; }, ptr);
  return ptr;
}

BENCH_DEFINE(ffkx_skiplist_update) {
  bpf_register_heap(&heap);
  auto elem = ffkx_skiplist_elem_alloc(key, key_size, value, value_size);
  if (!elem) {
    return ENOMEM;
  }
  struct ffkx_skiplist_elem **prev = ffkx_skiplist_prev;
  // Cast to void, as this is a buffer we will read/write values from/to
  // as scratch space
  cast(void, prev);
  struct ffkx_skiplist_elem *head = ffkx_skiplist_head;
  struct ffkx_skiplist_elem *curr = head;
  int level = head->height - 1;
  scalar_cast(level);

  while (curr && level >= 0) {
    prev[level] = curr;
    struct ffkx_skiplist_elem *ptr = *ffkx_skiplist_nextp(curr, level);
    if (ptr == NULL) {
      --level;
    } else {
      int cmp = bpf_bench_skiplist_cmp(ptr->buf, key, key_size);
      if (cmp == 0) {
        // Treat as value > so that deletes can match,
        // otherwise typically we just return 0 here
        // FIXME: return 0;
        --level;
      } else if (cmp > 0) {
        --level;
      } else {
        curr = ptr;
      }
    }
    // FIXME: For convergence
    level = scalar_cast(level);
    cond_break;
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

BENCH_DEFINE(ffkx_skiplist_lookup) {
  bpf_register_heap(&heap);

  struct ffkx_skiplist_elem *head = ffkx_skiplist_head;
  struct ffkx_skiplist_elem *curr = head;
  int level = head->height - 1;

  while (curr && level >= 0) {
    struct ffkx_skiplist_elem *ptr = *ffkx_skiplist_nextp(curr, level);
    if (ptr == NULL) {
      level--;
    } else {
      int cmp = bpf_bench_skiplist_cmp(ptr->buf, key, key_size);
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
    cond_break;
  }
  return ENOENT;
}

BENCH_DEFINE(ffkx_skiplist_delete) {
  bpf_register_heap(&heap);
  struct ffkx_skiplist_elem *head = ffkx_skiplist_head;
  struct ffkx_skiplist_elem *curr = head;
  int level = head->height - 1;

  struct ffkx_skiplist_elem **prev = ffkx_skiplist_prev;
  // Cast to void, as this is a buffer we will read/write values from/to
  // as scratch space
  cast(void, prev);

  int cmp = 1;
  while (curr && level >= 0) {
    struct ffkx_skiplist_elem *ptr = *ffkx_skiplist_nextp(curr, level);
    prev[level] = curr;
    if (ptr == NULL) {
      level--;
    } else {
      cmp = bpf_bench_skiplist_cmp(ptr->buf, key, key_size);
      if (cmp >= 0) {
        level--;
      } else {
        curr = ptr;
      }
    }
    level = scalar_cast(level);
    cond_break;
  }

  if (curr && !cmp) {
    struct ffkx_skiplist_elem *del = curr->next[0];
    for (int i = del->height - 1; i >= 0; cond_break, i--) {
      // prev[i]
      auto pprev = prev + i;
      cast(void, pprev);
      auto prev_i = *pprev;
      cast(typeof(*prev_i), prev_i);
      // prev[i]->next[i] = del->next[i];
      *ffkx_skiplist_nextp(prev_i, i) = *ffkx_skiplist_nextp(del, i);
      i = scalar_cast(i);
    }
    return 0;
  }
  return ENOENT;
}

BENCH_REGISTER(ffkx_skiplist_update);
BENCH_REGISTER(ffkx_skiplist_lookup);
BENCH_REGISTER(ffkx_skiplist_delete);

// BPF Skiplist

int bpf_bench_skiplist_update(struct ffkx_skiplist_elem *head__ign, struct ffkx_skiplist_elem *node__ign) __ksym;

BENCH_DEFINE(bpf_skiplist_update) {
  bpf_register_heap(&heap);
  auto elem = ffkx_skiplist_elem_alloc(key, key_size, value, value_size);
  if (!elem) {
    return ENOMEM;
  }
  return bpf_bench_skiplist_update(ffkx_conv_hptr(ffkx_skiplist_head), ffkx_conv_hptr(elem));
}

int bpf_bench_skiplist_lookup(struct ffkx_skiplist_elem *head__ign, void *key__ign, u32 key_size) __ksym;

BENCH_DEFINE(bpf_skiplist_lookup) {
  bpf_register_heap(&heap);
  return bpf_bench_skiplist_lookup(ffkx_conv_hptr(ffkx_skiplist_head), key, key_size);
}

int bpf_bench_skiplist_delete(struct ffkx_skiplist_elem *head__ign, void *key__ign, u32 key_size) __ksym;

BENCH_DEFINE(bpf_skiplist_delete) {
  bpf_register_heap(&heap);
  return bpf_bench_skiplist_delete(ffkx_conv_hptr(ffkx_skiplist_head), key, key_size);
}

BENCH_REGISTER(bpf_skiplist_update);
BENCH_REGISTER(bpf_skiplist_lookup);
BENCH_REGISTER(bpf_skiplist_delete);

/// -- Sketches -- ///

// FIXME: Wheere to put?
#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))
/// FIXME: move to util
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct countsketch *ffkx_countsketch;
static struct countsketch bpf_countsketch;

// add element and determine count
static void __always_inline bpf_countsketch_add(struct countsketch *cs, void *element, __u64 len) {
  // Calculate just a single hash and re-use it to update and query the sketch
  uint64_t h = fasthash64(element, len, SEED_HASHFN);

  uint16_t hashes[4];
  hashes[0] = (h & 0xFFFF);
  hashes[1] = h >> 16 & 0xFFFF;
  hashes[2] = h >> 32 & 0xFFFF;
  hashes[3] = h >> 48 & 0xFFFF;

  _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);

    if (CHECK_BIT(hashes[i], 31)) {
      NO_TEAR_ADD(cs->values[i][target_idx], 1);
    } else {
      NO_TEAR_ADD(cs->values[i][target_idx], -1);
    }
  }

  return;
}

// add element and determine count
static void __always_inline ffkx_countsketch_add(struct countsketch *cs, void *element, __u64 len) {
  // Calculate just a single hash and re-use it to update and query the sketch
  uint64_t h = fasthash64(element, len, SEED_HASHFN);

  uint16_t hashes[4];
  hashes[0] = (h & 0xFFFF);
  hashes[1] = h >> 16 & 0xFFFF;
  hashes[2] = h >> 32 & 0xFFFF;
  hashes[3] = h >> 48 & 0xFFFF;

  _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);

    auto ptr = &cs->values[i][target_idx];
    cast(void, ptr);
    if (CHECK_BIT(hashes[i], 31)) {
      NO_TEAR_ADD(*ptr, 1);
    } else {
      NO_TEAR_ADD(*ptr, -1);
    }
  }

  return;
}

struct countmin *ffkx_countminsketch;
static struct countmin bpf_countminsketch;

static void __always_inline bpf_countmin_add(struct countmin *cm, void *element, __u64 len) {
  // Calculate just a single hash and re-use it to update and query the sketch
  uint64_t h = fasthash64(element, len, SEED_HASHFN);

  uint16_t hashes[4];
  hashes[0] = (h & 0xFFFF);
  hashes[1] = h >> 16 & 0xFFFF;
  hashes[2] = h >> 32 & 0xFFFF;
  hashes[3] = h >> 48 & 0xFFFF;

  _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);
    NO_TEAR_ADD(cm->values[i][target_idx], 1);
  }
  return;
}

static void __always_inline ffkx_countmin_add(struct countmin *cm, void *element, __u64 len) {
  // Calculate just a single hash and re-use it to update and query the sketch
  uint64_t h = fasthash64(element, len, SEED_HASHFN);

  uint16_t hashes[4];
  hashes[0] = (h & 0xFFFF);
  hashes[1] = h >> 16 & 0xFFFF;
  hashes[2] = h >> 32 & 0xFFFF;
  hashes[3] = h >> 48 & 0xFFFF;

  _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);
    auto ptr = &cm->values[i][target_idx];
    cast(void, ptr);
    NO_TEAR_ADD(*ptr, 1);
  }
  return;
}

SEC("tc")
int bench_sketch_init(struct __sk_buff *ctx) {
  if (!ffkx_countsketch || !ffkx_countminsketch) {
    return ENOMEM;
  }
  return 0;
}

BENCH_DEFINE(ffkx_countsketch) {
  bpf_register_heap(&heap);
  auto cs = ffkx_countsketch;
  ffkx_countsketch_add(cs, key, key_size);
  return 0;
}

BENCH_DEFINE(ffkx_countminsketch) {
  bpf_register_heap(&heap);
  auto cms = ffkx_countminsketch;
  ffkx_countmin_add(cms, key, key_size);
  return 0;
}

BENCH_REGISTER(ffkx_countsketch);
BENCH_REGISTER(ffkx_countminsketch);

BENCH_DEFINE(bpf_countsketch) {
  bpf_countsketch_add(&bpf_countsketch, key, key_size);
  return 0;
}

BENCH_DEFINE(bpf_countminsketch) {
  bpf_countmin_add(&bpf_countminsketch, key, key_size);
  return 0;
}

BENCH_REGISTER(bpf_countsketch);
BENCH_REGISTER(bpf_countminsketch);

// Martix Multiplication?
/*
BENCH_DEFINE(bpf_memcmp) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }
  (void)bpf_ffkx_memequal(ffkx_conv_hptr(p), value, value_size);
  return 0;
}

BENCH_DEFINE(bpf_memcpy) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }
  bpf_ffkx_memcpy(ffkx_conv_hptr(p), value, value_size);
  return 0;
}

BENCH_REGISTER(bpf_memcmp);
BENCH_REGISTER(bpf_memcpy);

// Memory Copy

BENCH_DEFINE(ffkx_memset) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }
  ffkx_for(int i = ffkx_zero; i < value_size; i++) {
    char *buf = p + i;
    cast(void, buf);
    *buf = 0;
  }
  return 0;
}

BENCH_DEFINE(ffkx_memcmp) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }
  volatile int x = 0;
  int ret;

  ffkx_for(int i = ffkx_zero; i < value_size; i++) {
    char *buf = p + i;
    cast(void, buf);
    if (*buf == ((char *)value)[i]) {
      ret++;
    }
  }
  return ret + x;
}

BENCH_DEFINE(ffkx_memcmp8) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }
  volatile int x = 0;
  int ret = 0;

  ffkx_for(int i = ffkx_zero; i < value_size; i++) {
    char *buf = p + i;
    cast(void, buf);
    if (value_size - i >= 8) {
      ret += *(u64 *)buf == *(u64 *)(value + i);
      i += 8;
    } else if (*buf == ((char *)value)[i]) {
      ret++;
    }
  }
  return ret * x;
}

BENCH_DEFINE(ffkx_memcpy) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }

  ffkx_for(int i = ffkx_zero; i < value_size; i++) {
    char *buf = p + i;
    cast(void, buf);
    *buf = ((char *)value)[i];
  }
  return 0;
}

BENCH_DEFINE(ffkx_memcpy8) {
  bpf_register_heap(&heap);

  void *p = ffkx_malloc(value_size);
  if (!p) {
    return ENOMEM;
  }

  ffkx_for(int i = ffkx_zero; i < value_size; i++) {
    char *buf = p + i;
    cast(void, buf);
    if (value_size - i >= 8) {
      *(u64 *)buf = *(u64 *)(value + i);
      i += 8;
      continue;
    }
    *buf = ((char *)value)[i];
  }
  return 0;
}

BENCH_REGISTER(ffkx_memset);
BENCH_REGISTER(ffkx_memcmp);
BENCH_REGISTER(ffkx_memcmp8);
BENCH_REGISTER(ffkx_memcpy);
BENCH_REGISTER(ffkx_memcpy8);
*/
BENCH_DEFINE(bpf_nop) { return 0; }

BENCH_REGISTER(bpf_nop);

char _license[] SEC("license") = "GPL";
