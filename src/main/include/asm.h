#ifndef ASM_H
#define ASM_H

#ifdef __APPLE__
#define CNAME(s) _##s
#else
#define CNAME(s) s
#endif

#define ENTRY(name)         \
        .align 4;           \
        .globl CNAME(name); \
        CNAME(name):

#endif /* ASM_H */
