// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aesavs.h"

void parse_kv(char *line, char key[64], char value[1024]) {
    char *end = strchr(line, '\n');
    char *c = strchr(line, '=');

    if (*line == '[') line++;
    if (*(--end) == '\r') *end-- = '\0';
    if (*end == ']') *end-- = '\0';

    if (c) {
        *(c-1) = '\0';
        strcpy(key, line);
        strcpy(value, c + 2);
    } else {
        strcpy(key, line);
    }
}

uint8_t hex_value(char c) {
    if      (c <= '9') return c - '0';
    else if (c <= 'F') return c - 'A' + 10;
    else               return c - 'a' + 10;
}

void decode(char *name, char *hex, param *p) {
    uint8_t *value = p->value;
    p->len = 0;

    if (*hex == '\0') {
        return;
    }

    for (char *c = hex; *c; c++) {
        uint8_t high = hex_value(*c++ & 0x7f);
        uint8_t low  = hex_value(*c   & 0x7f);
        *value++ = (high << 4) | low;
        p->len++;
    }
}

void fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    exit(1);
}
