#include "kalki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

static ScaCheck *build_checks(int *count) {
    static ScaCheck checks[64];
    int idx = 0;

    struct stat st;

    snprintf(checks[idx].check_id, 64, "CIS-1.1.1");
    snprintf(checks[idx].name, 256, "File permissions on /etc/passwd");
    snprintf(checks[idx].description, 512, "Ensure /etc/passwd has 644 permissions");
    if (stat("/etc/passwd", &st) == 0) {
        checks[idx].passed = ((st.st_mode & 0777) == 0644);
    }
    snprintf(checks[idx].detail, 512, "Expected: 644, Actual: %o", (unsigned)(st.st_mode & 0777));
    idx++;

    snprintf(checks[idx].check_id, 64, "CIS-1.1.2");
    snprintf(checks[idx].name, 256, "File permissions on /etc/shadow");
    snprintf(checks[idx].description, 512, "Ensure /etc/shadow has 000 permissions");
    if (stat("/etc/shadow", &st) == 0) {
        checks[idx].passed = ((st.st_mode & 0777) == 0000);
    }
    snprintf(checks[idx].detail, 512, "Expected: 000, Actual: %o", (unsigned)(st.st_mode & 0777));
    idx++;

    snprintf(checks[idx].check_id, 64, "CIS-1.1.3");
    snprintf(checks[idx].name, 256, "File permissions on /etc/ssh/sshd_config");
    snprintf(checks[idx].description, 512, "Ensure sshd_config has 600 permissions");
    if (stat("/etc/ssh/sshd_config", &st) == 0) {
        checks[idx].passed = ((st.st_mode & 0777) == 0600);
    }
    snprintf(checks[idx].detail, 512, "Expected: 600, Actual: %o", (unsigned)(st.st_mode & 0777));
    idx++;

    char *sshd_config = read_file("/etc/ssh/sshd_config");
    if (sshd_config) {
        snprintf(checks[idx].check_id, 64, "CIS-2.1.1");
        snprintf(checks[idx].name, 256, "SSH root login");
        snprintf(checks[idx].description, 512, "Ensure PermitRootLogin is set to no");
        char *root_login = strstr(sshd_config, "PermitRootLogin");
        checks[idx].passed = (root_login && strstr(root_login, "no"));
        snprintf(checks[idx].detail, 512, "Check PermitRootLogin setting in sshd_config");
        idx++;
        free(sshd_config);
    }

    char *pam_config = read_file("/etc/pam.d/common-password");
    if (!pam_config) pam_config = read_file("/etc/pam.d/system-auth");
    if (pam_config) {
        snprintf(checks[idx].check_id, 64, "CIS-5.1.1");
        snprintf(checks[idx].name, 256, "Password complexity");
        snprintf(checks[idx].description, 512, "Ensure password complexity is enabled");
        checks[idx].passed = (strstr(pam_config, "pam_cracklib") != NULL ||
                             strstr(pam_config, "pam_pwquality") != NULL);
        snprintf(checks[idx].detail, 512, "Check for pam_cracklib or pam_pwquality modules");
        idx++;
        free(pam_config);
    }

    char *login_defs = read_file("/etc/login.defs");
    if (login_defs) {
        char *line = login_defs;
        char *next;
        while (line && *line) {
            next = strchr(line, '\n');
            if (next) *next++ = '\0';

            if (strstr(line, "PASS_MAX_DAYS")) {
                int days;
                sscanf(line, "PASS_MAX_DAYS %d", &days);
                snprintf(checks[idx].check_id, 64, "CIS-5.2.1");
                snprintf(checks[idx].name, 256, "Password max age");
                snprintf(checks[idx].description, 512, "Ensure PASS_MAX_DAYS is 90 or less");
                checks[idx].passed = (days <= 90);
                snprintf(checks[idx].detail, 512, "Current: %d days", days);
                idx++;
            }
            if (strstr(line, "PASS_MIN_DAYS")) {
                int days;
                sscanf(line, "PASS_MIN_DAYS %d", &days);
                snprintf(checks[idx].check_id, 64, "CIS-5.2.2");
                snprintf(checks[idx].name, 256, "Password min days");
                snprintf(checks[idx].description, 512, "Ensure PASS_MIN_DAYS is 7 or more");
                checks[idx].passed = (days >= 7);
                snprintf(checks[idx].detail, 512, "Current: %d days", days);
                idx++;
            }
            line = next;
        }
        free(login_defs);
    }

    char sysctl_output[4096] = {0};
    if (run_command("sysctl net.ipv4.ip_forward", sysctl_output, sizeof(sysctl_output)) == 0) {
        snprintf(checks[idx].check_id, 64, "CIS-3.1.1");
        snprintf(checks[idx].name, 256, "IP forwarding");
        snprintf(checks[idx].description, 512, "Ensure IP forwarding is disabled");
        checks[idx].passed = (strstr(sysctl_output, "= 0") != NULL);
        snprintf(checks[idx].detail, 512, "%s", sysctl_output);
        idx++;
    }

    *count = idx;
    return checks;
}

int sca_init(void) { return 0; }

int sca_run(ScaReport *report) {
    memset(report, 0, sizeof(ScaReport));

    int count = 0;
    ScaCheck *checks = build_checks(&count);

    report->checks = malloc(sizeof(ScaCheck) * count);
    if (!report->checks) return -1;

    memcpy(report->checks, checks, sizeof(ScaCheck) * count);
    report->count = count;
    report->total = count;

    for (int i = 0; i < count; i++) {
        if (report->checks[i].passed) {
            report->passed++;
        } else {
            report->failed++;
        }
    }

    return 0;
}

void sca_free_report(ScaReport *report) {
    free(report->checks);
    report->checks = NULL;
    report->count = 0;
}
