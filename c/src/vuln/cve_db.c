#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CVE_DB_SIZE 128

typedef struct {
    char id[32];
    char package[64];
    char description[256];
    int severity;
    char fixed_version[32];
} CveEntry;

static CveEntry cve_db[CVE_DB_SIZE];
static int cve_count = 0;

int cve_db_init(void) {
    cve_count = 0;
    CveEntry entries[] = {
        {"CVE-2023-45866", "openssl", "Double free in OpenSSL", 7, "1.1.1k"},
        {"CVE-2023-4806", "openssl", "POLY1305 MAC bug", 5, "1.1.1w"},
        {"CVE-2023-24329", "glibc", "off-by-one in _nl_get_recipient()", 7, "2.34"},
        {"CVE-2022-25265", "systemd", "Memory leak in systemd-resolved", 6, "249"},
        {"CVE-2023-24329", "python3", "open() allows symlinks", 5, "3.10"},
        {"CVE-2023-34058", "openssh", "Double free in OpenSSH", 7, "8.9"},
        {"CVE-2023-38820", "curl", "Integer overflow in libcurl", 6, "7.76"},
    };
    int count = sizeof(entries) / sizeof(CveEntry);
    for (int i = 0; i < count && i < CVE_DB_SIZE; i++) {
        memcpy(&cve_db[cve_count], &entries[i], sizeof(CveEntry));
        cve_count++;
    }
    return 0;
}

int cve_db_search(const char *package, const char *version, VulnEntry *out, int *count) {
    if (!package || !count) return -1;
    *count = 0;
    for (int i = 0; i < cve_count; i++) {
        int match = (strcmp(cve_db[i].package, package) == 0) ||
                    (strstr(package, cve_db[i].package) != NULL);
        if (match && cve_db[i].fixed_version[0]) {
            if (strcmp(version, cve_db[i].fixed_version) < 0) {
                if (out) {
                    strncpy(out[*count].cve_id, cve_db[i].id, 31);
                    strncpy(out[*count].package, package, 127);
                    strncpy(out[*count].installed_version, version, 63);
                    strncpy(out[*count].fixed_version, cve_db[i].fixed_version, 63);
                    out[*count].severity = cve_db[i].severity;
                }
                (*count)++;
            }
        }
    }
    return *count;
}
