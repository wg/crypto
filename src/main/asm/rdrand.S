/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * Secure random number generation for 64-bit x86-64
 * systems supporting the System V AMD64 ABI and the
 * RDRAND instruction.
 *
 * uint8_t rdrand_bytes(uint8_t *dst, size_t len, uint32_t retries);
 */

#include "asm.h"

ENTRY(rdrand_bytes)
    movq %rsi, %r11
    shrq   $3, %r11
    testq %r11, %r11
    jz tail

    leaq (%rdi,%r11,8), %r10

    leaq quads_loop(%rip), %r9
    xorl %eax, %eax
    .align 4, 0x90
quads:
    rdrandq %rcx
    jnc retry
quads_loop:
    movq %rcx, (%rdi,%rax,8)
    incq %rax
    cmpq %r11, %rax
    jb quads

    movq %r10, %rdi
tail:
    andq $7, %rsi
    testq %rsi, %rsi
    jz done

    leaq tail_loop(%rip), %r9
    xorl %eax, %eax
    rdrandq %rcx
    jnc retry
    .align 4, 0x90
tail_loop:
    movb %cl, (%rdi,%rax)
    shrq $8, %rcx
    incq %rax
    cmpq %rax, %rsi
    jne tail_loop
done:
    movb $1, %al
    ret

retry:
    movq %rdx, %r8
retry_loop:
    rdrandq %rcx
    jnc retry_dec
    jmpq *%r9
retry_dec:
    decq %r8
    jnz retry_loop
    movb $0, %al
    ret
