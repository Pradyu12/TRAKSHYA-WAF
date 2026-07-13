#include "kalki.h"
#include <stdio.h>
#include <string.h>

int lockdown_posture(void) {
    int ret = 0;
    char output[256] = {0};
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.tcp_syncookies=1");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.conf.all.rp_filter=1");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.conf.default.rp_filter=1");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.tcp_syn_retries=3");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.tcp_synack_retries=2");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.tcp_max_syn_backlog=256");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.icmp_echo_ignore_all=1");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "iptables -P INPUT DROP 2>/dev/null");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "iptables -A INPUT -i lo -j ACCEPT");
    ret += run_command(cmd, output, sizeof(output));

    return ret;
}

int restore_posture(void) {
    int ret = 0;
    char output[256] = {0};
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.tcp_syncookies=0");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.conf.all.rp_filter=0");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.icmp_echo_ignore_all=0");
    ret += run_command(cmd, output, sizeof(output));

    snprintf(cmd, sizeof(cmd), "iptables -P INPUT ACCEPT 2>/dev/null");

    return ret;
}
