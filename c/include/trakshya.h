#ifndef TRAKSHYA_H
#define TRAKSHYA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>

#define TRAKSHYA_MAX_PATH 4096
#define TRAKSHYA_MAX_ENTRIES 1024
#define TRAKSHYA_API_PORT 9001

/* HTTP response helpers */
typedef struct {
    int status_code;
    char *content_type;
    char *body;
    size_t body_len;
} HttpResponse;

/* ------ HIDS ------ */
typedef struct {
    char timestamp[64];
    char source_ip[64];
    char username[64];
    char event_type[64];
    char details[512];
} AuthLogEntry;

typedef struct {
    int total_entries;
    int failed_logins;
    int sudo_attempts;
    int ssh_attempts;
    char **suspicious_ips;
    int suspicious_count;
} HidsReport;

int hids_init(void);
int hids_scan(HidsReport *report);
void hids_free_report(HidsReport *report);

/* ------ FIM ------ */
typedef struct {
    char path[TRAKSHYA_MAX_PATH];
    char hash[65];
    time_t last_modified;
    off_t file_size;
} FileBaseline;

typedef struct {
    char path[TRAKSHYA_MAX_PATH];
    char expected_hash[65];
    char actual_hash[65];
    const char *status;
} FileChange;

typedef struct {
    FileChange *changes;
    int count;
    int capacity;
} FimReport;

int fim_init(void);
int fim_baseline_create(const char *paths[], int count);
int fim_scan(FimReport *report);
void fim_free_report(FimReport *report);

/* ------ SCA ------ */
typedef struct {
    char check_id[64];
    char name[256];
    char description[512];
    bool passed;
    char detail[512];
} ScaCheck;

typedef struct {
    ScaCheck *checks;
    int count;
    int passed;
    int failed;
    int total;
} ScaReport;

int sca_init(void);
int sca_run(ScaReport *report);
void sca_free_report(ScaReport *report);

/* ------ Vulnerability Scanner ------ */
typedef struct {
    char cve_id[32];
    char package[128];
    char installed_version[64];
    char fixed_version[64];
    int severity;
} VulnEntry;

typedef struct {
    VulnEntry *entries;
    int count;
} VulnReport;

int vuln_init(void);
int vuln_scan(VulnReport *report);
void vuln_free_report(VulnReport *report);

/* ------ Active Response ------ */
typedef struct {
    char ip[64];
    int duration_secs;
    bool success;
} BlockResult;

int active_response_init(void);
int block_ip(const char *ip, int duration_secs, BlockResult *result);
int unblock_ip(const char *ip);
int lockdown_posture(void);
int restore_posture(void);
int kill_process_by_port(int port);

/* ------ Utility ------ */
char *read_file(const char *path);
int write_file(const char *path, const char *content);
int run_command(const char *cmd, char *output, size_t output_size);
char *trim_whitespace(char *str);
char *sha256_file(const char *path, char *output);
int validate_ip(const char *ip);

/* ------ API ------ */
int start_api_server(void);
int api_send_report(const char *endpoint, const char *json_data);

#endif /* TRAKSHYA_H */