/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * Side-channel resistant constant-time memory comparison
 * for 64-bit x86-64 systems using the System V AMD64 ABI.
 *
 * uint8_t compare(uint8_t *a, uint8_t *b, size_t len);
 */

#include "asm.h"

ENTRY(compare)        
    xorq %rax, %rax

    movq %rdx, %rcx
    shr    $4, %rcx
    jz cmp8

    pxor %xmm1, %xmm1
    .align 4
loop16:
    movdqu (%rdi), %xmm0
    pxor   (%rsi), %xmm0
    por     %xmm0, %xmm1
    addq $16, %rdi
    addq $16, %rsi
    decq %rcx
    jnz loop16

    ptest %xmm1, %xmm1
    setnz %al
cmp8:
    movq %rdx, %r9
    andq $15,  %r9
    shrq $3,   %r9
    jz cmp1

    xorq %rcx, %rcx
    movzb %al, %r10
    .align 4
loop8:
    movq (%rdi, %rcx, 8), %r8
    xorq (%rsi, %rcx, 8), %r8
    orq %r8, %r10
    incq %rcx
    cmpq %r9, %rcx
    jb loop8

    testq %r10, %r10
    setnz %al

    shlq $3, %rcx
    add %rcx, %rdi
    add %rcx, %rsi
cmp1:
    andq $7, %rdx
    jz done

    xorq %rcx, %rcx
    movzb %al, %r10
    .align 4
loop1:
    movb (%rdi, %rcx), %r8b
    xor  (%rsi, %rcx), %r8b
    or %r8b, %r10b
    incq %rcx
    cmpq %rdx, %rcx
    jb loop1

    test %r10b, %r10b
    setnz %al
done:
    ret
