// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.bpf.h>
#include <bpf_memalloc.bpf.h>

private(ekc) struct bpf_spin_lock lock;
private(ekc) struct bpf_list_head list __contains(foo, node);

struct foo {
  struct bpf_list_node node;
  unsigned long data;
};

struct efoo {
  struct elist_node *next;
  struct elist_node *prev;
  unsigned long data;
};

struct list_head ekc_list;
struct list_head *__uptr(arena) ekc_listp = &ekc_list;

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next) {
  next->prev = new;
  new->next = next;
  new->prev = prev;
  WRITE_ONCE(prev->next, new);
}

static inline void list_add(struct list_head *new, struct list_head *head) { __list_add(new, head, head->next); }

SEC("tc")
int ekc_ll_insert(struct __sk_buff *ctx) {
  ekc_listp = bpf_translate_from_uptr(bpf_uptr_force_cast(&ekc_list, &arena, bpf_core_type_id_local(typeof(ekc_list))));
  int i = 100;
  while (i--) {
    struct efoo *f = emalloc(typeof(*f));
    if (!f) return TC_ACT_SHOT;
    bpf_spin_lock(&lock);
    list_add(ekc_listp, (struct list_head *)&f->next);
    bpf_spin_unlock(&lock);
  }
  return TC_ACT_OK;
}

SEC("tc")
int bpf_ll_insert(struct __sk_buff *ctx) {
  int i = 100;
  while (i--) {
    struct foo *f = bpf_obj_new(typeof(*f));
    if (!f) return TC_ACT_SHOT;
    bpf_spin_lock(&lock);
    bpf_list_push_front(&list, &f->node);
    bpf_spin_unlock(&lock);
  }
  return TC_ACT_OK;
}
