#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

extern char *sha256_file(const char *path, char *output);

int sha256_compare(const char *filepath, const char *expected_hash) {
    char actual_hash[65] = {0};
    if (!sha256_file(filepath, actual_hash)) return -1;
    return strcmp(actual_hash, expected_hash);
}
