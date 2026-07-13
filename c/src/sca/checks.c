#include "kalki.h"
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>

/* Additional SCA check functions (placeholder) */

int check_file_permissions(const char *path, mode_t expected) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (st.st_mode & 0777) == expected ? 0 : 1;
}

int check_user_in_group(const char *username, const char *groupname) {
    char cmd[256];
    char result[128] = {0};
    snprintf(cmd, sizeof(cmd), "groups %s", username);
    if (run_command(cmd, result, sizeof(result)) != 0) return -1;
    return (strstr(result, groupname) != NULL) ? 0 : 1;
}
