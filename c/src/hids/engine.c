#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char ip[64];
    int failure_count;
    time_t first_seen;
    time_t last_seen;
} SuspiciousIp;

static SuspiciousIp suspicious_ips[1024];
static int suspicious_count = 0;

int hids_init(void) {
    memset(suspicious_ips, 0, sizeof(suspicious_ips));
    suspicious_count = 0;
    return 0;
}

static int find_or_add_ip(const char *ip) {
    for (int i = 0; i < suspicious_count; i++) {
        if (strcmp(suspicious_ips[i].ip, ip) == 0) {
            return i;
        }
    }
    if (suspicious_count < 1024) {
        strncpy(suspicious_ips[suspicious_count].ip, ip, 63);
        suspicious_ips[suspicious_count].first_seen = time(NULL);
        suspicious_ips[suspicious_count].failure_count = 0;
        return suspicious_count++;
    }
    return -1;
}

int hids_scan(HidsReport *report) {
    memset(report, 0, sizeof(HidsReport));

    char *auth_log = read_file("/var/log/auth.log");
    if (!auth_log) {
        auth_log = read_file("/var/log/secure");
    }
    if (!auth_log) {
        auth_log = read_file("/var/log/syslog");
    }
    if (!auth_log) return -1;

    char *local_list[256];
    int susp_idx = 0;

    char *line = auth_log;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next = '\0';

        if (strstr(line, "Failed password")) {
            report->failed_logins++;
            char *from = strstr(line, "from ");
            if (from) {
                char ip[64] = {0};
                sscanf(from + 5, "%63s", ip);
                if (!validate_ip(ip)) {
                    goto next_line;
                }
                int idx = find_or_add_ip(ip);
                if (idx >= 0) {
                    suspicious_ips[idx].failure_count++;
                    suspicious_ips[idx].last_seen = time(NULL);
                    if (suspicious_ips[idx].failure_count >= 3) {
                        int already = 0;
                        for (int j = 0; j < susp_idx; j++) {
                            if (strcmp(local_list[j], ip) == 0) { already = 1; break; }
                        }
                        if (!already && susp_idx < 256) {
                            local_list[susp_idx] = strdup(ip);
                            susp_idx++;
                        }
                    }
                }
            }
        }

        if (strstr(line, "sudo") || strstr(line, "sudo:")) {
            report->sudo_attempts++;
        }

        if (strstr(line, "sshd") || strstr(line, "ssh:")) {
            report->ssh_attempts++;
        }

next_line:
        line = next ? next + 1 : NULL;
    }

    report->total_entries = report->failed_logins + report->sudo_attempts + report->ssh_attempts;

    if (susp_idx > 0) {
        report->suspicious_ips = malloc(sizeof(char *) * susp_idx);
        if (report->suspicious_ips) {
            memcpy(report->suspicious_ips, local_list, sizeof(char *) * susp_idx);
            report->suspicious_count = susp_idx;
        } else {
            for (int i = 0; i < susp_idx; i++) free(local_list[i]);
            report->suspicious_count = 0;
        }
    } else {
        report->suspicious_ips = NULL;
        report->suspicious_count = 0;
    }

    free(auth_log);
    return 0;
}

void hids_free_report(HidsReport *report) {
    if (report->suspicious_ips) {
        for (int i = 0; i < report->suspicious_count; i++) {
            free(report->suspicious_ips[i]);
        }
        free(report->suspicious_ips);
        report->suspicious_ips = NULL;
    }
    report->suspicious_count = 0;
}
