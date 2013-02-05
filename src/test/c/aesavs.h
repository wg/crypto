#ifndef AESAVS_H
#define AESAVS_H

typedef struct {
    uint8_t value[1024];
    size_t  len;
} param;

void parse_kv(char *, char[64], char[1024]);
uint8_t hex_value(char);
void decode(char *, char *, param *);
void fail(const char *, ...);

#endif /* AESAVS_H */
