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
#include <ekc_list.bpf.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

uint64_t ekcache_allocmap_base_ptr;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_MMAPABLE);
} allocmap SEC(".maps");

#define BPF_F_TRANS_USER 1

struct {
  __uint(type, BPF_MAP_TYPE_ARENA);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_MMAPABLE | BPF_F_TRANS_USER);
} arena SEC(".maps");
#include <ekcache.countsketch.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct pkt_md);
  __uint(max_entries, 1);
} dropcount SEC(".maps");

//struct countsketch __uptr(arena) * ekcache_countsketch_base_ptr;

uint64_t ekcache_bench_infinite_loop_iter_count = -1;

SEC("tc")
int ekcache_bench_infinite_loop(struct __sk_buff *ctx) {
  int i = -1;

  bpf_for(i, 0, BPF_MAX_LOOPS) {}
  ekcache_bench_infinite_loop_iter_count = i;
  return TC_ACT_OK;
}

uint64_t ekcache_bench_infinite_loop_throw_iter_count = -1;

SEC("tc")
int ekcache_bench_infinite_loop_throw(struct __sk_buff *ctx) {
  // Always true, but the verifier does not know so. If we don't have the
  // branch, the verifier sees that we always throw and deletes later
  // instructions which exit the program.
  if (ctx->len) {
    loop {}
  }
  ekcache_bench_infinite_loop_throw_iter_count = BPF_MAX_LOOPS;
  return TC_ACT_OK;
}

uint64_t ekcache_bench_linked_list_head_ptr;

static __always_inline void *ekcache_translate_allocmap_pointer(void *p, void *userp) {
  // TODO(kkd): Assert that p is always non-NULL, but this can be called from
  // inside iterator loop which does not allow safe unwinding due to on-stack
  // references.
  uint64_t offset = bpf_unknown_cast(userp) - ekcache_allocmap_base_ptr;
  return bpf_untrusted_obj_cast(bpf_unknown_cast(p) + offset, struct ekc_list_head);
}

static __always_inline void *ekcache_translate_allocmap_pointer_countsketch(void *p, void *userp) {
  // TODO(kkd): Assert that p is always non-NULL, but this can be called from
  // inside iterator loop which does not allow safe unwinding due to on-stack
  // references.
  uint64_t offset = bpf_unknown_cast(userp) - ekcache_allocmap_base_ptr;
  return bpf_untrusted_obj_cast(bpf_unknown_cast(p) + offset, struct countsketch);
}

unsigned long arena_map_kernel_base_address;

SEC("tc")
int ekcache_get_arena_map_base(struct __sk_buff *ctx) {
  struct bpf_arena *map = (void *)&arena;
//  arena_map_kernel_base_address = (unsigned long)map->value;
  return 0;
}

void bpf_register_arena(void *) __ksym;

SEC("xdp")
int ekcache_bench_count_sketch(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  bpf_register_arena(&arena);

  u64 nh_off = 0;
  /* Where should I import? */
  struct eth_hdr *eth = data;
  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) goto DROP;

  uint16_t h_proto = eth->proto;

#pragma unroll
  for (int i = 0; i < 2; i++) {
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
      struct vlan_hdr *vhdr;
      vhdr = data + nh_off;
      nh_off += sizeof(struct vlan_hdr);
      if (data + nh_off > data_end) goto DROP;
      h_proto = vhdr->h_vlan_encapsulated_proto;
    }
  }

  switch (h_proto) {
    case bpf_htons(ETH_P_IP):
      break;
    default:
      return XDP_PASS;
  }

  struct pkt_5tuple pkt;

  struct iphdr *ip = data + nh_off;
  if ((void *)&ip[1] > data_end) goto DROP;

  pkt.src_ip = ip->saddr;
  pkt.dst_ip = ip->daddr;
  pkt.proto = ip->protocol;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      struct tcp_hdr *tcp = NULL;
      tcp = data + nh_off + sizeof(*ip);
      if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end) goto DROP;
      pkt.src_port = tcp->source;
      pkt.dst_port = tcp->dest;
      break;
    }
    case IPPROTO_UDP: {
      struct udphdr *udp = NULL;
      udp = data + nh_off + sizeof(*ip);
      if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end) goto DROP;
      pkt.src_port = udp->source;
      pkt.dst_port = udp->dest;
      break;
    }
    default:
      goto DROP;
  }

  uint32_t zero = 0;
  struct countsketch *cs;

  // cs will be allocated from userspace
 // cs = ekcache_countsketch_base_ptr;
  if (!cs) {
    bpf_printk("Invalid entry in the countsketch sketch");
    goto DROP;
  }

#ifdef COUNTMIN
  countmin_add(cs, &pkt, sizeof(pkt));
#else
  countsketch_add(cs, &pkt, sizeof(pkt));
#endif

  struct pkt_md *md;
  uint32_t index = 0;
  md = bpf_map_lookup_elem(&dropcount, &index);
  if (md) {
#ifdef COUNT_PACKETS
    NO_TEAR_INC(md->drop_cnt);
#endif
#ifdef COUNT_BYTES
    uint16_t pkt_len = (uint16_t)(data_end - data);
    NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif
  }

#ifdef ACTION_DROP
  return XDP_DROP;
#else
  return bpf_redirect(_OUTPUT_INTERFACE_IFINDEX, 0);
#endif

DROP:;
  bpf_printk("Error. Dropping packet\n");
  return XDP_DROP;
}

SEC("tc")
int ekcache_bench_search_linked_list(struct __sk_buff *ctx) {
  void *region = bpf_map_lookup_elem(&allocmap, &(int){0});
  struct ekc_list_head *head;
  int i = -1;

  bpf_assert_with(region, TC_ACT_SHOT);
  head = ekcache_translate_allocmap_pointer(region, (void *)ekcache_bench_linked_list_head_ptr);
  loop {
    head = ekcache_translate_allocmap_pointer(region, head->next);
    if (!head->next) {
      break;
    }
  }
  return TC_ACT_OK;
}

uint64_t ekcache_strcmp_string1;
uint64_t ekcache_strcmp_string2;

SEC("tc")
int ekcache_strcmp(struct __sk_buff *ctx) {
  void *region = bpf_map_lookup_elem(&allocmap, &(int){0});
  const char *s1, *s2;

  bpf_assert_with(region, TC_ACT_SHOT);
  s1 = ekcache_translate_allocmap_pointer(region, (void *)ekcache_strcmp_string1);
  s2 = ekcache_translate_allocmap_pointer(region, (void *)ekcache_strcmp_string2);
  return bpf_strcmp(s1, s2);
}

char _license[] SEC("license") = "GPL";
