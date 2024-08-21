// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_HEAP_BPF_H
#define FFKX_BPF_FFKX_HEAP_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_helpers.h>

/* emit instruction:
 * rX = rX .off = BPF_ADDR_SPACE_CAST .imm32 = (dst_as << 16) | src_as
 */
// FIXME: Fix the names, also, document why we emit guard + type cast together,
//  we were seeing cases of compiler reusing old value instead of the guarded
//  register. "memory" operand is used to ensure that all future instructions
//  should only be emitted after this volatile block, which means previous
//  values are not legal to reuse, without the memory operand reordering may
//  occur (not literally), so compiler feels free to reuse old loaded value.
#ifndef bpf_addr_space_cast_same
#define bpf_addr_space_cast_same(var, id_var, imm)                     \
  asm volatile(                                                        \
      ".byte 0xBF;		\
		     .ifc %[reg], r0;		\
		     .byte 0x00;		\
		     .endif;			\
		     .ifc %[reg], r1;		\
		     .byte 0x11;		\
		     .endif;			\
		     .ifc %[reg], r2;		\
		     .byte 0x22;		\
		     .endif;			\
		     .ifc %[reg], r3;		\
		     .byte 0x33;		\
		     .endif;			\
		     .ifc %[reg], r4;		\
		     .byte 0x44;		\
		     .endif;			\
		     .ifc %[reg], r5;		\
		     .byte 0x55;		\
		     .endif;			\
		     .ifc %[reg], r6;		\
		     .byte 0x66;		\
		     .endif;			\
		     .ifc %[reg], r7;		\
		     .byte 0x77;		\
		     .endif;			\
		     .ifc %[reg], r8;		\
		     .byte 0x88;		\
		     .endif;			\
		     .ifc %[reg], r9;		\
		     .byte 0x99;		\
		     .endif;			\
		     .short %[off];		\
		     .long %[as];                             \
      .byte 0xBF;		\
.ifc %[id]%[reg], r0r0;     \
.byte 0x00;   \
.endif;     \
.ifc %[id]%[reg], r0r1;     \
.byte 0x01;   \
.endif;     \
.ifc %[id]%[reg], r0r2;     \
.byte 0x02;   \
.endif;     \
.ifc %[id]%[reg], r0r3;     \
.byte 0x03;   \
.endif;     \
.ifc %[id]%[reg], r0r4;     \
.byte 0x04;   \
.endif;     \
.ifc %[id]%[reg], r0r5;     \
.byte 0x05;   \
.endif;     \
.ifc %[id]%[reg], r0r6;     \
.byte 0x06;   \
.endif;     \
.ifc %[id]%[reg], r0r7;     \
.byte 0x07;   \
.endif;     \
.ifc %[id]%[reg], r0r8;     \
.byte 0x08;   \
.endif;     \
.ifc %[id]%[reg], r0r9;     \
.byte 0x09;   \
.endif;     \
.ifc %[id]%[reg], r1r0;     \
.byte 0x10;   \
.endif;     \
.ifc %[id]%[reg], r1r1;     \
.byte 0x11;   \
.endif;     \
.ifc %[id]%[reg], r1r2;     \
.byte 0x12;   \
.endif;     \
.ifc %[id]%[reg], r1r3;     \
.byte 0x13;   \
.endif;     \
.ifc %[id]%[reg], r1r4;     \
.byte 0x14;   \
.endif;     \
.ifc %[id]%[reg], r1r5;     \
.byte 0x15;   \
.endif;     \
.ifc %[id]%[reg], r1r6;     \
.byte 0x16;   \
.endif;     \
.ifc %[id]%[reg], r1r7;     \
.byte 0x17;   \
.endif;     \
.ifc %[id]%[reg], r1r8;     \
.byte 0x18;   \
.endif;     \
.ifc %[id]%[reg], r1r9;     \
.byte 0x19;   \
.endif;     \
.ifc %[id]%[reg], r2r0;     \
.byte 0x20;   \
.endif;     \
.ifc %[id]%[reg], r2r1;     \
.byte 0x21;   \
.endif;     \
.ifc %[id]%[reg], r2r2;     \
.byte 0x22;   \
.endif;     \
.ifc %[id]%[reg], r2r3;     \
.byte 0x23;   \
.endif;     \
.ifc %[id]%[reg], r2r4;     \
.byte 0x24;   \
.endif;     \
.ifc %[id]%[reg], r2r5;     \
.byte 0x25;   \
.endif;     \
.ifc %[id]%[reg], r2r6;     \
.byte 0x26;   \
.endif;     \
.ifc %[id]%[reg], r2r7;     \
.byte 0x27;   \
.endif;     \
.ifc %[id]%[reg], r2r8;     \
.byte 0x28;   \
.endif;     \
.ifc %[id]%[reg], r2r9;     \
.byte 0x29;   \
.endif;     \
.ifc %[id]%[reg], r3r0;     \
.byte 0x30;   \
.endif;     \
.ifc %[id]%[reg], r3r1;     \
.byte 0x31;   \
.endif;     \
.ifc %[id]%[reg], r3r2;     \
.byte 0x32;   \
.endif;     \
.ifc %[id]%[reg], r3r3;     \
.byte 0x33;   \
.endif;     \
.ifc %[id]%[reg], r3r4;     \
.byte 0x34;   \
.endif;     \
.ifc %[id]%[reg], r3r5;     \
.byte 0x35;   \
.endif;     \
.ifc %[id]%[reg], r3r6;     \
.byte 0x36;   \
.endif;     \
.ifc %[id]%[reg], r3r7;     \
.byte 0x37;   \
.endif;     \
.ifc %[id]%[reg], r3r8;     \
.byte 0x38;   \
.endif;     \
.ifc %[id]%[reg], r3r9;     \
.byte 0x39;   \
.endif;     \
.ifc %[id]%[reg], r4r0;     \
.byte 0x40;   \
.endif;     \
.ifc %[id]%[reg], r4r1;     \
.byte 0x41;   \
.endif;     \
.ifc %[id]%[reg], r4r2;     \
.byte 0x42;   \
.endif;     \
.ifc %[id]%[reg], r4r3;     \
.byte 0x43;   \
.endif;     \
.ifc %[id]%[reg], r4r4;     \
.byte 0x44;   \
.endif;     \
.ifc %[id]%[reg], r4r5;     \
.byte 0x45;   \
.endif;     \
.ifc %[id]%[reg], r4r6;     \
.byte 0x46;   \
.endif;     \
.ifc %[id]%[reg], r4r7;     \
.byte 0x47;   \
.endif;     \
.ifc %[id]%[reg], r4r8;     \
.byte 0x48;   \
.endif;     \
.ifc %[id]%[reg], r4r9;     \
.byte 0x49;   \
.endif;     \
.ifc %[id]%[reg], r5r0;     \
.byte 0x50;   \
.endif;     \
.ifc %[id]%[reg], r5r1;     \
.byte 0x51;   \
.endif;     \
.ifc %[id]%[reg], r5r2;     \
.byte 0x52;   \
.endif;     \
.ifc %[id]%[reg], r5r3;     \
.byte 0x53;   \
.endif;     \
.ifc %[id]%[reg], r5r4;     \
.byte 0x54;   \
.endif;     \
.ifc %[id]%[reg], r5r5;     \
.byte 0x55;   \
.endif;     \
.ifc %[id]%[reg], r5r6;     \
.byte 0x56;   \
.endif;     \
.ifc %[id]%[reg], r5r7;     \
.byte 0x57;   \
.endif;     \
.ifc %[id]%[reg], r5r8;     \
.byte 0x58;   \
.endif;     \
.ifc %[id]%[reg], r5r9;     \
.byte 0x59;   \
.endif;     \
.ifc %[id]%[reg], r6r0;     \
.byte 0x60;   \
.endif;     \
.ifc %[id]%[reg], r6r1;     \
.byte 0x61;   \
.endif;     \
.ifc %[id]%[reg], r6r2;     \
.byte 0x62;   \
.endif;     \
.ifc %[id]%[reg], r6r3;     \
.byte 0x63;   \
.endif;     \
.ifc %[id]%[reg], r6r4;     \
.byte 0x64;   \
.endif;     \
.ifc %[id]%[reg], r6r5;     \
.byte 0x65;   \
.endif;     \
.ifc %[id]%[reg], r6r6;     \
.byte 0x66;   \
.endif;     \
.ifc %[id]%[reg], r6r7;     \
.byte 0x67;   \
.endif;     \
.ifc %[id]%[reg], r6r8;     \
.byte 0x68;   \
.endif;     \
.ifc %[id]%[reg], r6r9;     \
.byte 0x69;   \
.endif;     \
.ifc %[id]%[reg], r7r0;     \
.byte 0x70;   \
.endif;     \
.ifc %[id]%[reg], r7r1;     \
.byte 0x71;   \
.endif;     \
.ifc %[id]%[reg], r7r2;     \
.byte 0x72;   \
.endif;     \
.ifc %[id]%[reg], r7r3;     \
.byte 0x73;   \
.endif;     \
.ifc %[id]%[reg], r7r4;     \
.byte 0x74;   \
.endif;     \
.ifc %[id]%[reg], r7r5;     \
.byte 0x75;   \
.endif;     \
.ifc %[id]%[reg], r7r6;     \
.byte 0x76;   \
.endif;     \
.ifc %[id]%[reg], r7r7;     \
.byte 0x77;   \
.endif;     \
.ifc %[id]%[reg], r7r8;     \
.byte 0x78;   \
.endif;     \
.ifc %[id]%[reg], r7r9;     \
.byte 0x79;   \
.endif;     \
.ifc %[id]%[reg], r8r0;     \
.byte 0x80;   \
.endif;     \
.ifc %[id]%[reg], r8r1;     \
.byte 0x81;   \
.endif;     \
.ifc %[id]%[reg], r8r2;     \
.byte 0x82;   \
.endif;     \
.ifc %[id]%[reg], r8r3;     \
.byte 0x83;   \
.endif;     \
.ifc %[id]%[reg], r8r4;     \
.byte 0x84;   \
.endif;     \
.ifc %[id]%[reg], r8r5;     \
.byte 0x85;   \
.endif;     \
.ifc %[id]%[reg], r8r6;     \
.byte 0x86;   \
.endif;     \
.ifc %[id]%[reg], r8r7;     \
.byte 0x87;   \
.endif;     \
.ifc %[id]%[reg], r8r8;     \
.byte 0x88;   \
.endif;     \
.ifc %[id]%[reg], r8r9;     \
.byte 0x89;   \
.endif;     \
.ifc %[id]%[reg], r9r0;     \
.byte 0x90;   \
.endif;     \
.ifc %[id]%[reg], r9r1;     \
.byte 0x91;   \
.endif;     \
.ifc %[id]%[reg], r9r2;     \
.byte 0x92;   \
.endif;     \
.ifc %[id]%[reg], r9r3;     \
.byte 0x93;   \
.endif;     \
.ifc %[id]%[reg], r9r4;     \
.byte 0x94;   \
.endif;     \
.ifc %[id]%[reg], r9r5;     \
.byte 0x95;   \
.endif;     \
.ifc %[id]%[reg], r9r6;     \
.byte 0x96;   \
.endif;     \
.ifc %[id]%[reg], r9r7;     \
.byte 0x97;   \
.endif;     \
.ifc %[id]%[reg], r9r8;     \
.byte 0x98;   \
.endif;     \
.ifc %[id]%[reg], r9r9;     \
.byte 0x99;   \
.endif;     \
		     .short %[off];		\
		     .long %[as2]"                                                  \
      : [reg] "+r"(var)                                                \
      : [id] "r"(id_var), [off] "i"(1), [as] "i"((imm)), [as2] "i"(-1) \
      : "memory")
#endif

/* emit instruction:
 * rX = rX .off = BPF_ADDR_SPACE_CAST .imm32 = (dst_as << 16) | src_as
 */
#ifndef bpf_addr_space_cast
#define bpf_addr_space_cast(var, id_var, imm)         \
  asm volatile(                                       \
      ".byte 0xBF;		\
.ifc %[id]%[reg], r0r0;     \
.byte 0x00;   \
.endif;     \
.ifc %[id]%[reg], r0r1;     \
.byte 0x01;   \
.endif;     \
.ifc %[id]%[reg], r0r2;     \
.byte 0x02;   \
.endif;     \
.ifc %[id]%[reg], r0r3;     \
.byte 0x03;   \
.endif;     \
.ifc %[id]%[reg], r0r4;     \
.byte 0x04;   \
.endif;     \
.ifc %[id]%[reg], r0r5;     \
.byte 0x05;   \
.endif;     \
.ifc %[id]%[reg], r0r6;     \
.byte 0x06;   \
.endif;     \
.ifc %[id]%[reg], r0r7;     \
.byte 0x07;   \
.endif;     \
.ifc %[id]%[reg], r0r8;     \
.byte 0x08;   \
.endif;     \
.ifc %[id]%[reg], r0r9;     \
.byte 0x09;   \
.endif;     \
.ifc %[id]%[reg], r1r0;     \
.byte 0x10;   \
.endif;     \
.ifc %[id]%[reg], r1r1;     \
.byte 0x11;   \
.endif;     \
.ifc %[id]%[reg], r1r2;     \
.byte 0x12;   \
.endif;     \
.ifc %[id]%[reg], r1r3;     \
.byte 0x13;   \
.endif;     \
.ifc %[id]%[reg], r1r4;     \
.byte 0x14;   \
.endif;     \
.ifc %[id]%[reg], r1r5;     \
.byte 0x15;   \
.endif;     \
.ifc %[id]%[reg], r1r6;     \
.byte 0x16;   \
.endif;     \
.ifc %[id]%[reg], r1r7;     \
.byte 0x17;   \
.endif;     \
.ifc %[id]%[reg], r1r8;     \
.byte 0x18;   \
.endif;     \
.ifc %[id]%[reg], r1r9;     \
.byte 0x19;   \
.endif;     \
.ifc %[id]%[reg], r2r0;     \
.byte 0x20;   \
.endif;     \
.ifc %[id]%[reg], r2r1;     \
.byte 0x21;   \
.endif;     \
.ifc %[id]%[reg], r2r2;     \
.byte 0x22;   \
.endif;     \
.ifc %[id]%[reg], r2r3;     \
.byte 0x23;   \
.endif;     \
.ifc %[id]%[reg], r2r4;     \
.byte 0x24;   \
.endif;     \
.ifc %[id]%[reg], r2r5;     \
.byte 0x25;   \
.endif;     \
.ifc %[id]%[reg], r2r6;     \
.byte 0x26;   \
.endif;     \
.ifc %[id]%[reg], r2r7;     \
.byte 0x27;   \
.endif;     \
.ifc %[id]%[reg], r2r8;     \
.byte 0x28;   \
.endif;     \
.ifc %[id]%[reg], r2r9;     \
.byte 0x29;   \
.endif;     \
.ifc %[id]%[reg], r3r0;     \
.byte 0x30;   \
.endif;     \
.ifc %[id]%[reg], r3r1;     \
.byte 0x31;   \
.endif;     \
.ifc %[id]%[reg], r3r2;     \
.byte 0x32;   \
.endif;     \
.ifc %[id]%[reg], r3r3;     \
.byte 0x33;   \
.endif;     \
.ifc %[id]%[reg], r3r4;     \
.byte 0x34;   \
.endif;     \
.ifc %[id]%[reg], r3r5;     \
.byte 0x35;   \
.endif;     \
.ifc %[id]%[reg], r3r6;     \
.byte 0x36;   \
.endif;     \
.ifc %[id]%[reg], r3r7;     \
.byte 0x37;   \
.endif;     \
.ifc %[id]%[reg], r3r8;     \
.byte 0x38;   \
.endif;     \
.ifc %[id]%[reg], r3r9;     \
.byte 0x39;   \
.endif;     \
.ifc %[id]%[reg], r4r0;     \
.byte 0x40;   \
.endif;     \
.ifc %[id]%[reg], r4r1;     \
.byte 0x41;   \
.endif;     \
.ifc %[id]%[reg], r4r2;     \
.byte 0x42;   \
.endif;     \
.ifc %[id]%[reg], r4r3;     \
.byte 0x43;   \
.endif;     \
.ifc %[id]%[reg], r4r4;     \
.byte 0x44;   \
.endif;     \
.ifc %[id]%[reg], r4r5;     \
.byte 0x45;   \
.endif;     \
.ifc %[id]%[reg], r4r6;     \
.byte 0x46;   \
.endif;     \
.ifc %[id]%[reg], r4r7;     \
.byte 0x47;   \
.endif;     \
.ifc %[id]%[reg], r4r8;     \
.byte 0x48;   \
.endif;     \
.ifc %[id]%[reg], r4r9;     \
.byte 0x49;   \
.endif;     \
.ifc %[id]%[reg], r5r0;     \
.byte 0x50;   \
.endif;     \
.ifc %[id]%[reg], r5r1;     \
.byte 0x51;   \
.endif;     \
.ifc %[id]%[reg], r5r2;     \
.byte 0x52;   \
.endif;     \
.ifc %[id]%[reg], r5r3;     \
.byte 0x53;   \
.endif;     \
.ifc %[id]%[reg], r5r4;     \
.byte 0x54;   \
.endif;     \
.ifc %[id]%[reg], r5r5;     \
.byte 0x55;   \
.endif;     \
.ifc %[id]%[reg], r5r6;     \
.byte 0x56;   \
.endif;     \
.ifc %[id]%[reg], r5r7;     \
.byte 0x57;   \
.endif;     \
.ifc %[id]%[reg], r5r8;     \
.byte 0x58;   \
.endif;     \
.ifc %[id]%[reg], r5r9;     \
.byte 0x59;   \
.endif;     \
.ifc %[id]%[reg], r6r0;     \
.byte 0x60;   \
.endif;     \
.ifc %[id]%[reg], r6r1;     \
.byte 0x61;   \
.endif;     \
.ifc %[id]%[reg], r6r2;     \
.byte 0x62;   \
.endif;     \
.ifc %[id]%[reg], r6r3;     \
.byte 0x63;   \
.endif;     \
.ifc %[id]%[reg], r6r4;     \
.byte 0x64;   \
.endif;     \
.ifc %[id]%[reg], r6r5;     \
.byte 0x65;   \
.endif;     \
.ifc %[id]%[reg], r6r6;     \
.byte 0x66;   \
.endif;     \
.ifc %[id]%[reg], r6r7;     \
.byte 0x67;   \
.endif;     \
.ifc %[id]%[reg], r6r8;     \
.byte 0x68;   \
.endif;     \
.ifc %[id]%[reg], r6r9;     \
.byte 0x69;   \
.endif;     \
.ifc %[id]%[reg], r7r0;     \
.byte 0x70;   \
.endif;     \
.ifc %[id]%[reg], r7r1;     \
.byte 0x71;   \
.endif;     \
.ifc %[id]%[reg], r7r2;     \
.byte 0x72;   \
.endif;     \
.ifc %[id]%[reg], r7r3;     \
.byte 0x73;   \
.endif;     \
.ifc %[id]%[reg], r7r4;     \
.byte 0x74;   \
.endif;     \
.ifc %[id]%[reg], r7r5;     \
.byte 0x75;   \
.endif;     \
.ifc %[id]%[reg], r7r6;     \
.byte 0x76;   \
.endif;     \
.ifc %[id]%[reg], r7r7;     \
.byte 0x77;   \
.endif;     \
.ifc %[id]%[reg], r7r8;     \
.byte 0x78;   \
.endif;     \
.ifc %[id]%[reg], r7r9;     \
.byte 0x79;   \
.endif;     \
.ifc %[id]%[reg], r8r0;     \
.byte 0x80;   \
.endif;     \
.ifc %[id]%[reg], r8r1;     \
.byte 0x81;   \
.endif;     \
.ifc %[id]%[reg], r8r2;     \
.byte 0x82;   \
.endif;     \
.ifc %[id]%[reg], r8r3;     \
.byte 0x83;   \
.endif;     \
.ifc %[id]%[reg], r8r4;     \
.byte 0x84;   \
.endif;     \
.ifc %[id]%[reg], r8r5;     \
.byte 0x85;   \
.endif;     \
.ifc %[id]%[reg], r8r6;     \
.byte 0x86;   \
.endif;     \
.ifc %[id]%[reg], r8r7;     \
.byte 0x87;   \
.endif;     \
.ifc %[id]%[reg], r8r8;     \
.byte 0x88;   \
.endif;     \
.ifc %[id]%[reg], r8r9;     \
.byte 0x89;   \
.endif;     \
.ifc %[id]%[reg], r9r0;     \
.byte 0x90;   \
.endif;     \
.ifc %[id]%[reg], r9r1;     \
.byte 0x91;   \
.endif;     \
.ifc %[id]%[reg], r9r2;     \
.byte 0x92;   \
.endif;     \
.ifc %[id]%[reg], r9r3;     \
.byte 0x93;   \
.endif;     \
.ifc %[id]%[reg], r9r4;     \
.byte 0x94;   \
.endif;     \
.ifc %[id]%[reg], r9r5;     \
.byte 0x95;   \
.endif;     \
.ifc %[id]%[reg], r9r6;     \
.byte 0x96;   \
.endif;     \
.ifc %[id]%[reg], r9r7;     \
.byte 0x97;   \
.endif;     \
.ifc %[id]%[reg], r9r8;     \
.byte 0x98;   \
.endif;     \
.ifc %[id]%[reg], r9r9;     \
.byte 0x99;   \
.endif;     \
		     .short %[off];		\
		     .long %[as]"                                 \
      : [reg] "+r"(var)                               \
      : [id] "r"(id_var), [off] "i"(1), [as] "i"(imm) \
      : "memory")
#endif

// LLVM shits its pants when passing void to bpf_core_type_id_local
#define ffkx_type_id_resolve(type) \
  ({ __builtin_types_compatible_p(typeof((void *){0}), typeof((type *){0})) ? 0 : bpf_core_type_id_local(type); })

// Casts a hptr into another type in verifier state.
#define __hptr_cast(type, p)                                      \
  ({                                                              \
    _Pragma("GCC diagnostic push");                               \
    _Pragma("GCC diagnostic ignored \"-Wvoid-ptr-dereference\""); \
    const int ___id = ffkx_type_id_resolve(type);                 \
    _Pragma("GCC diagnostic pop");                                \
    bpf_addr_space_cast(p, ___id, -1);                            \
    p;                                                            \
  })

// Emit a guard to mark pointer as trusted hptr, without translation.
// This means the pointer will simply be brought into heap domain, without
// regard for its value (NULL will become heap base address).
#define __hptr_guard(type, p)                                     \
  ({                                                              \
    _Pragma("GCC diagnostic push");                               \
    _Pragma("GCC diagnostic ignored \"-Wvoid-ptr-dereference\""); \
    const int ___id = ffkx_type_id_resolve(type);                 \
    _Pragma("GCC diagnostic pop");                                \
    bpf_addr_space_cast_same(p, ___id, 2);                        \
  })

// Emit a guard to mark pointer as trusted hptr, with translation.
// This means the pointer will be brought into heap domain respecting
// its value, NULL stays NULL while rest become heap addresses.
// This is strictly more expensive.
#define __hptr_guard_trans(type, p)                               \
  ({                                                              \
    _Pragma("GCC diagnostic push");                               \
    _Pragma("GCC diagnostic ignored \"-Wvoid-ptr-dereference\""); \
    const int ___id = ffkx_type_id_resolve(type);                 \
    _Pragma("GCC diagnostic pop");                                \
    bpf_addr_space_cast_same(p, ___id, 3);                        \
  })

// Simply switch the type of a heap pointer in verifier state.
#define type_cast(type, p) ({ __hptr_cast(type, p); })

// Cast non-NULL value to a heap pointer.
// WARNING: NULL-ness of argument won't be preserved. Hence, don't use on
// pointer values which might be NULL, and need to be checked after cast.
#define cast(type, p) ({ __hptr_guard(type, p); })

// Cast any unknown value (maybe NULL) to a heap pointer.
#define reinterpret_cast(type, p) ({ __hptr_guard_trans(type, p); })

void bpf_register_heap(void *map) __ksym;

#define ffkx_heap(size, flags)                 \
  struct {                                     \
    __uint(type, BPF_MAP_TYPE_HEAP);           \
    __uint(key_size, 4);                       \
    __uint(value_size, 4096);                  \
    __uint(max_entries, size * 262144);        \
    __uint(map_flags, BPF_F_MMAPABLE | flags); \
  }

#endif
