#include "kalki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int parse_auth_line(const char *line, AuthLogEntry *entry) {
    if (!line || !entry) return -1;
    memset(entry, 0, sizeof(AuthLogEntry));

    const char *patterns[] = {
        "Failed password",
        "Accepted password",
        "Invalid user",
        "Connection closed",
        "Break-in attempt",
        "sudo",
        "su"
    };

    for (int i = 0; i < 7; i++) {
        if (strstr(line, patterns[i])) {
            strncpy(entry->event_type, patterns[i], 63);
            break;
        }
    }

    if (strstr(line, "from ")) {
        const char *from = strstr(line, "from ");
        if (from) {
            sscanf(from + 5, "%63s", entry->source_ip);
        }
    }

    const char *user_marker = strstr(line, "for ");
    if (!user_marker) user_marker = strstr(line, "user ");
    if (user_marker) {
        user_marker += 4;
        char user[64] = {0};
        sscanf(user_marker, "%63s", user);
        char *end = strchr(user, ' ');
        if (end) *end = '\0';
        end = strchr(user, '\'');
        if (end) *end = '\0';
        strncpy(entry->username, user, 63);
    }

    strncpy(entry->details, line, 511);
    strncpy(entry->timestamp, line, 31);

    return 0;
}
