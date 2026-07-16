#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int active_response_init(void) {
    return 0;
}

int block_ip(const char *ip, int duration_secs, BlockResult *result) {
    memset(result, 0, sizeof(BlockResult));
    if (!validate_ip(ip)) {
        result->success = false;
        return -1;
    }
    strncpy(result->ip, ip, 63);
    result->duration_secs = duration_secs;

    char cmd[512];
    char output[256] = {0};

    snprintf(cmd, sizeof(cmd), "iptables -C INPUT -s %s -j DROP 2>/dev/null", ip);
    if (run_command(cmd, output, sizeof(output)) == 0) {
        result->success = true;
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "iptables -A INPUT -s %s -j DROP", ip);
    int ret = run_command(cmd, output, sizeof(output));
    result->success = (ret == 0);

    if (duration_secs > 0) {
        snprintf(cmd, sizeof(cmd),
            "(sleep %d && iptables -D INPUT -s %s -j DROP) &",
            duration_secs, ip);
        run_command(cmd, output, sizeof(output));
    }

    return ret;
}

int unblock_ip(const char *ip) {
    if (!validate_ip(ip)) return -1;
    char cmd[512];
    char output[256] = {0};
    snprintf(cmd, sizeof(cmd), "iptables -D INPUT -s %s -j DROP", ip);
    return run_command(cmd, output, sizeof(output));
}
