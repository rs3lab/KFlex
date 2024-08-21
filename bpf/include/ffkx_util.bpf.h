// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_UTIL_BPF_H
#define FFKX_BPF_FFKX_UTIL_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf/bpf_helpers.h>

#define auto __auto_type

#define ffkx_container_of(ptr, type, member)  \
  (type *)({                                  \
    void *__mptr = (void *)(ptr);             \
    __mptr = __mptr - offsetof(type, member); \
    type_cast(type, __mptr);                  \
    __mptr;                                   \
  })

u64 bpf_scalar_cast(u64) __ksym;

#define scalar_cast(ptr) bpf_scalar_cast((u64)ptr)

int bpf_iter_loop_new(struct bpf_iter_loop *) __ksym;
int *bpf_iter_loop_next(struct bpf_iter_loop *) __ksym;
void bpf_iter_loop_destroy(struct bpf_iter_loop *) __ksym;

static __always_inline void bpf_iter_loop_cleanup(struct bpf_iter_loop *it) { bpf_iter_loop_destroy(it); }

#define ffkx_for                                                                              \
  for (struct bpf_iter_loop ___it __attribute__((cleanup(bpf_iter_loop_cleanup))), *___p = ({ \
         bpf_iter_loop_new(&___it);                                                           \
         &___it;                                                                              \
       });                                                                                    \
       ___p; ___p = NULL) for

// TODO(kkd): Hack until we fix infinite loop bug
#define cond_break                                          \
  ({                                                        \
    __label__ l_break, l_continue;                          \
    asm volatile goto("may_goto %l[l_break]" :: ::l_break); \
    goto l_continue;                                        \
  l_break:                                                  \
    break;                                                  \
  l_continue:;                                              \
  })

#define ffkx_cond ({ bpf_iter_loop_next(&___it); })
//#define ffkx_cond ({ cond_break; bpf_iter_loop_next(&___it); })

#define ffkx_while(expr) ffkx_for(; (expr) && ffkx_cond;)

#define ffkx_loop ffkx_for(; ffkx_cond;)

#define ffkx_round_up(N, K) ((N + K - 1) / K * K)

#define ffkx_pow_of_2(N) (N && !(N & (N - 1)))

// Use global ffkx_zero as loop initializer to help covergence
static u64 ffkx_zero;

extern uint64_t ffkx_malloc_heap_kbase;
extern uint64_t ffkx_malloc_heap_kmask;

// Special functions to copy memory
void bpf_ffkx_memcpy(void *, void *, u64) __ksym;
bool bpf_ffkx_memequal(void *, void *, u64) __ksym;
bool bpf_ffkx_memcmp(void *, void *, u64) __ksym;

#define ffkx_conv_hptr(ptr) ((void *)((scalar_cast(ptr) & ffkx_malloc_heap_kmask) | ffkx_malloc_heap_kbase))

static __always_inline bool ffkx_memequal(void *dst, void *src, u64 size) {
  return bpf_ffkx_memequal(dst, src, size);
  /*
    // TODO(kkd): The problem might be that we skip guard emission when being
    // confused by loop convergence logic. One way might be to guard whenever we
    // are inside a loop on pointer increments. In the case below, we only read,
    // so it will be ok, but we should have guards in correct implementation.
    //
    // The other fix will be to disallow size > S16_MAX, but let's not add it now.
    ffkx_for(u64 i = ffkx_zero; i < size && ffkx_cond;) {
      u64 rem = size - i;
      if (rem > 8) {
        u64 *d = dst, *s = src;
        if (*d != *s) {
          return false;
        }
        dst += 8;
        src += 8;
        i += 8;
      } else if (rem > 4) {
        u32 *d = dst, *s = src;
        if (*d != *s) {
          return false;
        }
        dst += 4;
        src += 4;
        i += 4;
      } else {
        char *d = dst, *s = src;
        if (*d != *s) {
          return false;
        }
        dst++;
        src++;
        i++;
      }
    }
    return true;
  */
}

static __always_inline void ffkx_memcpy(void *dst, void *src, u64 size) { return bpf_ffkx_memcpy(dst, src, size); }

// heap map name is not needed, but meant for future use cases. Ignored for now.
#ifndef __hptr
#define __hptr __attribute__((btf_type_tag("hptr:heap")))
#endif

#endif
