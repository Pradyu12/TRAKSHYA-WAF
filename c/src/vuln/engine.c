#include "kalki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CVE_DB_PATH "/var/lib/kalki/cve.db"

typedef struct {
    char package[64];
    char version[32];
    int critical_vulns;
} ScanResult;

static ScanResult results[256];
static int result_count = 0;

int vuln_init(void) {
    result_count = 0;
    return 0;
}

static int scan_apt_packages(void) {
    char list_output[65536] = {0};
    if (run_command("dpkg -l", list_output, sizeof(list_output)) != 0 &&
        run_command("rpm -qa", list_output, sizeof(list_output)) != 0) {
        return -1;
    }

    char *line = list_output;
    char *next;
    while ((next = strchr(line, '\n')) && result_count < 256) {
        *next = '\0';
        // Process line looking for package name and version
        char name[64] = {0};
        char ver[32] = {0};
        if (name[0]) {
            strncpy(results[result_count].package, name, 63);
            strncpy(results[result_count].version, ver, 31);
            results[result_count].critical_vulns = 0; // would query cve_db
            result_count++;
        }
        line = next + 1;
    }
    return 0;
}

int vuln_scan(VulnReport *report) {
    memset(report, 0, sizeof(VulnReport));

    int entries = 0;
    VulnEntry buffer[64];

    char pkg_manifest[65536] = {0};
    int r = run_command("dpkg -l 2>/dev/null | tail -n +6 | awk '{print $2,$3}'", pkg_manifest, sizeof(pkg_manifest));
    if (r != 0) {
        run_command("rpm -qa 2>/dev/null", pkg_manifest, sizeof(pkg_manifest));
    }

    char *line = pkg_manifest;
    char *next;
    while ((next = strchr(line, '\n')) && entries < 64) {
        *next = '\0';
        char name[128] = {0};
        char ver[64] = {0};
        if (sscanf(line, "%127s %63s", name, ver) >= 1) {
            VulnEntry entry = {0};
            strncpy(entry.package, name, 127);
            strncpy(entry.installed_version, ver, 63);

            if (strstr(name, "openssl") || strstr(name, "libssl")) {
                if (strcmp(ver, "1.1.1") < 0) {
                    strncpy(entry.cve_id, "CVE-2023-0286", 31);
                    entry.severity = 7;
                    strncpy(entry.fixed_version, "1.1.1", 63);
                }
            }
            if (strstr(name, "libcrypto") || strstr(name, "libssl")) {
                if (strcmp(ver, "1.1.1") < 0) {
                    strncpy(entry.cve_id, "CVE-2023-0464", 31);
                    strncpy(entry.fixed_version, "1.1.1w", 63);
                    entry.severity = 5;
                }
            }
            if (strstr(name, "libsystemd")) {
                if (strcmp(ver, "249") < 0) {
                    strncpy(entry.cve_id, "CVE-2022-25265", 31);
                    strncpy(entry.fixed_version, "249", 63);
                    entry.severity = 6;
                }
            }
            if (strstr(name, "glibc") || strcmp(name, "libc6") == 0) {
                if (strcmp(ver, "2.34") < 0) {
                    strncpy(entry.cve_id, "CVE-2023-24329", 31);
                    strncpy(entry.fixed_version, "2.34", 63);
                    entry.severity = 7;
                }
            }

            if (entry.cve_id[0]) {
                memcpy(&buffer[entries], &entry, sizeof(VulnEntry));
                entries++;
            }
        }
        line = next + 1;
    }

    report->entries = malloc(sizeof(VulnEntry) * entries);
    if (!report->entries) return -1;
    memcpy(report->entries, buffer, sizeof(VulnEntry) * entries);
    report->count = entries;
    return 0;
}
void vuln_free_report(VulnReport *report) {
    free(report->entries);
    report->entries = NULL;
    report->count = 0;
}
