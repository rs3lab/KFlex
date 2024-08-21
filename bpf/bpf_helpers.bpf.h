// SPDX-License-Identifier: GPL-2.0
#ifndef EKCACHE_BPF_BPF_HELPERS_BPF_H
#define EKCACHE_BPF_BPF_HELPERS_BPF_H

// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

void bpf_preempt_disable(void) __ksym;
void bpf_preempt_enable(void) __ksym;

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define EKC_EXCEPTION_INF_LOOP (~0UL)

#define READ_ONCE(x) *(volatile typeof(x) *)(&(x))
#define WRITE_ONCE(x, value) (*(volatile typeof(x) *)(&(x)) = value)

void *bpf_rdonly_obj_cast(void *addr, __u32 type_id) __ksym;
u64 bpf_scalar_cast(u64 any) __ksym;
void *bpf_uptr_cast(void *addr, __u32 type_id) __ksym;
void *bpf_uptr_force_cast(void *addr, void *arena, __u32 type_id) __ksym;
void *bpf_translate_to_uptr(void *addr, void *arena, __u32 type_id) __ksym;
void *bpf_translate_from_uptr(void *addr) __ksym;

#define bpf_untrusted_cast(value, type) bpf_rdonly_cast((void *)(value), bpf_core_type_id_kernel(type))
#define bpf_untrusted_obj_cast(value, type) bpf_rdonly_obj_cast((void *)(value), bpf_core_type_id_local(type))
#define bpf_unknown_cast(value) bpf_scalar_cast((u64)(value))

#define BPF_MAX_LOOPS (8 * 1024 * 1024)

static inline void ekc_bpf_loop_iter_assert_dtor(void *p) {
  int *it = p;
  bpf_assert_with(*it != BPF_MAX_LOOPS - 1, EKC_EXCEPTION_INF_LOOP);
  bpf_assert_with(*it != -1, EKC_EXCEPTION_INF_LOOP);
}

#define loop                                                                                          \
  for (int ___i __attribute__((cleanup(ekc_bpf_loop_iter_assert_dtor))) = -1, ___j = 1; ___j; ___j--) \
  bpf_for(___i, 0, BPF_MAX_LOOPS)

static __always_inline int bpf_strcmp(const char *str1, const char *str2) {
  struct {
    const signed char s;
  } *s1, *s2;

  s1 = bpf_untrusted_obj_cast(str1, typeof(*s1));
  s2 = bpf_untrusted_obj_cast(str2, typeof(*s2));
  loop {
    if (!s1->s || (s1->s != s2->s)) {
      break;
    }
    s1 = bpf_untrusted_obj_cast(bpf_unknown_cast(s1) + 1, typeof(*s1));
    s2 = bpf_untrusted_obj_cast(bpf_unknown_cast(s2) + 1, typeof(*s2));
  }
  return s1->s - s2->s;
}

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

#endif
