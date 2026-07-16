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

    char *line = auth_log;
    char *next;
    char *suspicious_ips_list[256];
    int susp_idx = 0;

    while (line && *line) {
        next = strchr(line, '\n');
        if (next) *next = '\0';

        if (strstr(line, "Failed password")) {
            report->failed_logins++;
            char *from = strstr(line, "from ");
            if (from) {
                char ip[64] = {0};
                sscanf(from + 5, "%63s", ip);
                if (!validate_ip(ip)) {
                    line = next ? next + 1 : NULL;
                    continue;
                }
                int idx = find_or_add_ip(ip);
                if (idx >= 0) {
                    suspicious_ips[idx].failure_count++;
                    suspicious_ips[idx].last_seen = time(NULL);
                    if (suspicious_ips[idx].failure_count >= 3) {
                        int already = 0;
                        for (int j = 0; j < susp_idx; j++) {
                            if (strcmp(suspicious_ips_list[j], ip) == 0) { already = 1; break; }
                        }
                        if (!already && susp_idx < 256) {
                            suspicious_ips_list[susp_idx] = strdup(ip);
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

        line = next ? next + 1 : NULL;
    }

    report->total_entries = report->failed_logins + report->sudo_attempts + report->ssh_attempts;
    report->suspicious_ips = suspicious_ips_list;
    report->suspicious_count = susp_idx;

    free(auth_log);
    return 0;
}

void hids_free_report(HidsReport *report) {
    if (report->suspicious_ips) {
        for (int i = 0; i < report->suspicious_count; i++) {
            free(report->suspicious_ips[i]);
        }
        report->suspicious_ips = NULL;
    }
    report->suspicious_count = 0;
}
