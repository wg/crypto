/**
 * Copyright (C) 2012 - Will Glozer. All rights reserved.
 *
 * Memory zeroing in 16, 8, and 1 byte chunks for 64-bit
 * x86-64 systems using the System V AMD64 ABI.
 *
 * void zero(void *b, size_t len);
 */

#include "asm.h"

ENTRY(zero)        
    movq %rsi, %rcx
    shr    $4, %rcx
    jz zero8

    pxor %xmm1, %xmm1
    .align 4
loop16:
    movdqu %xmm1, (%rdi)
    addq $16, %rdi
    decq %rcx
    jnz loop16

zero8:
    movq %rsi, %r9
    andq $15,  %r9
    shrq $3,   %r9
    jz zero1

    xorq %rcx, %rcx
    xorq %rax, %rax
    .align 4
loop8:
    movq %rax, (%rdi, %rcx, 8)
    incq %rcx
    cmpq %r9, %rcx
    jb loop8

    shlq $3, %rcx
    add %rcx, %rdi
zero1:
    andq $7, %rsi
    jz done

    xorq %rcx, %rcx
    xorb %al, %al
    .align 4
loop1:
    movb %al, (%rdi, %rcx)
    incq %rcx
    cmpq %rsi, %rcx
    jb loop1
done:
    ret
