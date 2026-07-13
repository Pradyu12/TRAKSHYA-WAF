#include "kalki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>

char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }

    size_t n = fread(content, 1, size, f);
    content[n] = '\0';
    fclose(f);
    return content;
}

int write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

int run_command(const char *cmd, char *output, size_t output_size) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    size_t total = 0;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp) && total < output_size - 1) {
        size_t len = strlen(buf);
        if (total + len < output_size - 1) {
            memcpy(output + total, buf, len);
            total += len;
        }
    }
    output[total] = '\0';

    int status = pclose(fp);
    return WEXITSTATUS(status);
}

char *trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

char *sha256_file(const char *path, char *output) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    fclose(f);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
    return output;
}

int http_post_json(const char *url, const char *json_data, char *response, size_t response_size) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "curl -s -X POST '%s' -H 'Content-Type: application/json' -d '%s'",
        url, json_data);
    return run_command(cmd, response, response_size);
}

int validate_ip(const char *ip) {
    if (!ip || !*ip) return 0;

    size_t len = strlen(ip);
    if (len > 45) return 0;

    int dots = 0, colons = 0;
    for (size_t i = 0; i < len; i++) {
        char c = ip[i];
        if (c == '.') { dots++; continue; }
        if (c == ':') { colons++; continue; }
        if (!isxdigit((unsigned char)c)) return 0;
    }

    if (colons > 0 && dots > 0) return 0;
    if (dots > 3 || colons > 7) return 0;

    return 1;
}
