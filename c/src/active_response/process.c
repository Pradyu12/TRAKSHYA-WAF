#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

int kill_process_by_port(int port) {
    char cmd[256];
    char output[512] = {0};
    snprintf(cmd, sizeof(cmd), "lsof -ti :%d 2>/dev/null", port);
    if (run_command(cmd, output, sizeof(output)) != 0) {
        return -1;
    }

    char *line = output;
    char *next;
    int killed = 0;
    while ((next = strchr(line, '\n')) && killed < 10) {
        *next = '\0';
        int pid = atoi(line);
        if (pid > 0) {
            kill(pid, SIGKILL);
            killed++;
        }
        line = next + 1;
    }
    return killed > 0 ? 0 : -1;
}

static int is_safe_process_name(const char *name) {
    if (!name || !*name) return 0;
    size_t len = strlen(name);
    if (len > 128) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

int kill_process_by_name(const char *name) {
    if (!is_safe_process_name(name)) return -1;
    char cmd[256];
    char output[512] = {0};
    snprintf(cmd, sizeof(cmd), "pkill -f '%s' 2>/dev/null", name);
    return run_command(cmd, output, sizeof(output));
}
