// Copyright (C) 2012 - Will Glozer. All rights reserved.

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <libgen.h>

#include "aesavs.h"

extern int aes_kat(char *, FILE *);
extern int gcm_kat(char *, FILE *);
extern int cbc_mct(char *, FILE *);

typedef struct {
    char *pattern;
    int(*test)(char *, FILE *);
} suite;

int main(int argc, char **argv) {
    suite suites[] = {
        { "{CBC,ECB}{GFS,Key,Var}*.rsp", &aes_kat },
        { "gcm{Encrypt,Decrypt}*.rsp",   &gcm_kat },        
        { "CBCMCT*.rsp",                 &cbc_mct },        
    };
    int suite_count = sizeof(suites) / sizeof(suite);

    for (int s = 0; s < suite_count; s++) {
        char pattern[1024], cmd[1024];
        glob_t globs;
        
        sprintf(pattern, "src/test/resources/nist/%s", suites[s].pattern);
        if (glob(pattern, GLOB_BRACE, NULL, &globs)) {
            fail("unable to glob %s: %s\n", pattern, strerror(errno));
        }

        for (int i = 0; i < globs.gl_pathc; i++) {
            char *path     = globs.gl_pathv[i];
            char *filename = basename(path);
            FILE *file, *pipe;
            int tests, count = 0;

            assert(file = fopen(path, "r"));
            tests = suites[s].test(filename, file);
            fclose(file);

            sprintf(cmd, "grep -ic COUNT '%s'", path);
            assert(pipe = popen(cmd, "r"));
            assert(fscanf(pipe, "%d", &count) == 1);
            pclose(pipe);

            assert(count == tests);
        }

        globfree(&globs);
    }

    return 0;
}
