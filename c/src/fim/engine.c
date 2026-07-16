#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BASELINE_FILE "/var/lib/trakshya/fim_baseline.dat"
#define MAX_FILES 256

static FileBaseline baseline[MAX_FILES];
static int baseline_count = 0;
static int initialized = 0;

int fim_init(void) {
    memset(baseline, 0, sizeof(baseline));
    baseline_count = 0;
    initialized = 1;

    FILE *f = fopen(BASELINE_FILE, "r");
    if (f) {
        char line[4160];
        while (fgets(line, sizeof(line), f) && baseline_count < MAX_FILES) {
            line[strcspn(line, "\n")] = '\0';
            char *path = line;
            char *hash = strchr(line, '|');
            if (hash) {
                *hash = '\0';
                hash++;
                strncpy(baseline[baseline_count].path, path, TRAKSHYA_MAX_PATH - 1);
                strncpy(baseline[baseline_count].hash, hash, 64);
                struct stat st;
                if (stat(path, &st) == 0) {
                    baseline[baseline_count].last_modified = st.st_mtime;
                    baseline[baseline_count].file_size = st.st_size;
                }
                baseline_count++;
            }
        }
        fclose(f);
    }

    return 0;
}

int fim_baseline_create(const char *paths[], int count) {
    FILE *f = fopen(BASELINE_FILE, "w");
    if (!f) return -1;

    for (int i = 0; i < count && i < MAX_FILES; i++) {
        char hash[65] = {0};
        if (sha256_file(paths[i], hash)) {
            fprintf(f, "%s|%s\n", paths[i], hash);
            strncpy(baseline[baseline_count].path, paths[i], TRAKSHYA_MAX_PATH - 1);
            strncpy(baseline[baseline_count].hash, hash, 64);
            struct stat st;
            if (stat(paths[i], &st) == 0) {
                baseline[baseline_count].last_modified = st.st_mtime;
                baseline[baseline_count].file_size = st.st_size;
            }
            baseline_count++;
        }
    }

    fclose(f);
    return 0;
}

int fim_scan(FimReport *report) {
    if (!initialized) fim_init();
    memset(report, 0, sizeof(FimReport));

    report->changes = malloc(sizeof(FileChange) * baseline_count);
    if (!report->changes) return -1;
    report->capacity = baseline_count;
    report->count = 0;

    for (int i = 0; i < baseline_count; i++) {
        char current_hash[65] = {0};
        if (!sha256_file(baseline[i].path, current_hash)) {
            strncpy(report->changes[report->count].path, baseline[i].path, TRAKSHYA_MAX_PATH - 1);
            strncpy(report->changes[report->count].expected_hash, baseline[i].hash, 64);
            strncpy(report->changes[report->count].actual_hash, "", 64);
            report->changes[report->count].status = "deleted";
            report->count++;
            continue;
        }

        if (strcmp(current_hash, baseline[i].hash) != 0) {
            strncpy(report->changes[report->count].path, baseline[i].path, TRAKSHYA_MAX_PATH - 1);
            strncpy(report->changes[report->count].expected_hash, baseline[i].hash, 64);
            strncpy(report->changes[report->count].actual_hash, current_hash, 64);
            report->changes[report->count].status = "modified";
            report->count++;
        }
    }

    return 0;
}

void fim_free_report(FimReport *report) {
    free(report->changes);
    report->changes = NULL;
    report->count = 0;
    report->capacity = 0;
}
