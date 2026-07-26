#include "trakshya.h"
#include <stdio.h>
#include <string.h>

static int is_valid_chain(const char *chain) {
    if (!chain || !*chain) return 0;
    const char *valid[] = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING", NULL};
    for (int i = 0; valid[i]; i++) {
        if (strcmp(chain, valid[i]) == 0) return 1;
    }
    return 0;
}

int iptables_rule_exists(const char *chain, const char *ip) {
    if (!validate_ip(ip) || !is_valid_chain(chain)) return 0;
    char cmd[256];
    char output[128] = {0};
    snprintf(cmd, sizeof(cmd), "iptables -C %s -s %s -j DROP 2>/dev/null", chain, ip);
    return (run_command(cmd, output, sizeof(output)) == 0);
}

int iptables_add_rule(const char *chain, const char *ip) {
    if (!validate_ip(ip) || !is_valid_chain(chain)) return -1;
    char cmd[256];
    char output[128] = {0};
    snprintf(cmd, sizeof(cmd), "iptables -A %s -s %s -j DROP", chain, ip);
    return run_command(cmd, output, sizeof(output));
}

int iptables_remove_rule(const char *chain, const char *ip) {
    if (!validate_ip(ip) || !is_valid_chain(chain)) return -1;
    char cmd[256];
    char output[128] = {0};
    snprintf(cmd, sizeof(cmd), "iptables -D %s -s %s -j DROP", chain, ip);
    return run_command(cmd, output, sizeof(output));
}

int ufw_block_ip(const char *ip) {
    if (!validate_ip(ip)) return -1;
    char cmd[256];
    char output[128] = {0};
    snprintf(cmd, sizeof(cmd), "ufw deny from %s", ip);
    return run_command(cmd, output, sizeof(output));
}

int ufw_unblock_ip(const char *ip) {
    if (!validate_ip(ip)) return -1;
    char cmd[256];
    char output[128] = {0};
    snprintf(cmd, sizeof(cmd), "ufw delete deny from %s", ip);
    return run_command(cmd, output, sizeof(output));
}
