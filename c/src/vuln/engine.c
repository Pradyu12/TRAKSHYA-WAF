#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VULN_RESULTS 256

typedef struct {
    char package[64];
    char version[32];
    int critical_vulns;
} ScanResult;

static ScanResult results[MAX_VULN_RESULTS];
static int result_count = 0;

int vuln_init(void) {
    result_count = 0;
    return 0;
}

static int parse_dpkg_line(const char *line, char *name, size_t name_len, char *ver, size_t ver_len) {
    name[0] = '\0';
    ver[0] = '\0';

    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n') return 0;

    const char *status_end = strchr(p, ' ');
    if (!status_end) return 0;

    while (*status_end == ' ') status_end++;
    const char *pkg_name = status_end;
    while (*status_end && *status_end != ' ') status_end++;

    size_t nlen = status_end - pkg_name;
    if (nlen == 0 || nlen >= name_len) return 0;
    memcpy(name, pkg_name, nlen);
    name[nlen] = '\0';

    while (*status_end == ' ') status_end++;
    const char *pkg_ver = status_end;
    while (*status_end && *status_end != ' ' && *status_end != '\n') status_end++;

    size_t vlen = status_end - pkg_ver;
    if (vlen == 0 || vlen >= ver_len) return 0;
    memcpy(ver, pkg_ver, vlen);
    ver[vlen] = '\0';

    return 1;
}

int vuln_scan(VulnReport *report) {
    memset(report, 0, sizeof(VulnReport));

    int entries = 0;
    VulnEntry buffer[64];

    char pkg_manifest[65536] = {0};
    int r = run_command("dpkg -l 2>/dev/null | tail -n +6", pkg_manifest, sizeof(pkg_manifest));
    if (r != 0) {
        run_command("rpm -qa 2>/dev/null", pkg_manifest, sizeof(pkg_manifest));
    }

    char *line = pkg_manifest;
    while (line && *line && entries < 64) {
        char *next = strchr(line, '\n');
        if (next) *next = '\0';

        char name[128] = {0};
        char ver[64] = {0};
        if (parse_dpkg_line(line, name, sizeof(name), ver, sizeof(ver))) {
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

        line = next ? next + 1 : NULL;
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
