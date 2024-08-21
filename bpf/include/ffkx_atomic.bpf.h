// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_ATOMIC_BPF_H
#define FFKX_BPF_FFKX_ATOMIC_BPF_H

#define ffkx_barrier() asm volatile("" ::: "memory")

#define FFKX_READ_ONCE(X) *(volatile typeof(X) *)(&(X))
#define FFKX_WRITE_ONCE(X, VAL) (*(volatile typeof(X) *)(&(X)) = VAL)

#define ffkx_atomic_fetch_add(X, VAL) __sync_fetch_and_add(X, VAL)
#define ffkx_atomic_fetch_sub(X, VAL) __sync_fetch_and_sub(X, VAL)
#define ffkx_atomic_fetch_or(X, VAL) __sync_fetch_and_or(X, VAL)
#define ffkx_atomic_fetch_and(X, VAL) __sync_fetch_and_and(X, VAL)
#define ffkx_atomic_fetch_xor(X, VAL) __sync_fetch_and_xor(X, VAL)
#define ffkx_atomic_fetch_nand(X, VAL) __sync_fetch_and_nand(X, VAL)

#define ffkx_atomic_xchg(X, VAL) __sync_lock_test_and_set(X, VAL)
#define ffkx_atomic_cmpxchg(X, OLDVAL, VAL) __sync_val_compare_and_swap(X, OLDVAL, VAL)

// TODO(kkd): These are x86 specific, because we JIT BPF programs on x86 targets
// only. For now, hardcode the implementation, but use higher-level APIs in
// actual code so that we can correctly substitute implementation when BPF gains
// a memory model.
#define ffkx_smp_load_acquire(X) FFKX_READ_ONCE(*(X))
#define ffkx_smp_store_release(X, VAL) FFKX_WRITE_ONCE(*(X), VAL)

#define ffkx_smp_rmb() ffkx_barrier()
#define ffkx_smp_wmb() ffkx_barrier()
#define ffkx_smp_mb()                 \
  ({                                 \
    unsigned long i = 0;             \
    __sync_lock_test_and_set(&i, 0); \
  })

#define rcu_dereference(p) FFKX_READ_ONCE(p)
#define rcu_assign_pointer(p, val) ffkx_smp_store_release(&p, val)

#endif
