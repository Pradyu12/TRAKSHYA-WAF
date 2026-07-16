#include "trakshya.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <microhttpd.h>

static volatile int keep_running = 1;

void handle_signal(int sig) {
    keep_running = 0;
}

static enum MHD_Result api_handler(void *cls, struct MHD_Connection *connection,
                                   const char *url, const char *method,
                                   const char *version, const char *upload_data,
                                   size_t *upload_data_size, void **con_cls) {
    const char *response_str = "{\"status\": \"ok\", \"service\": \"trakshya-systemd\"}";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(response_str), (void *)response_str, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

int start_api_server(void) {
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,
        TRAKSHYA_API_PORT, NULL, NULL,
        &api_handler, NULL,
        MHD_OPTION_END);
    return daemon ? 0 : -1;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(stderr, "TRAKSHYA System Monitor starting on port %d...\n", TRAKSHYA_API_PORT);

    hids_init();
    fim_init();
    sca_init();
    vuln_init();
    active_response_init();

    if (start_api_server() != 0) {
        fprintf(stderr, "Failed to start API server\n");
        return 1;
    }

    while (keep_running) {
        HidsReport hids_report;
        FimReport fim_report;
        ScaReport sca_report;
        VulnReport vuln_report;

        if (hids_scan(&hids_report) == 0) {
            fprintf(stdout, "HIDS scan: %d failed logins, %d suspicious IPs\n",
                    hids_report.failed_logins, hids_report.suspicious_count);
            hids_free_report(&hids_report);
        }

        if (fim_scan(&fim_report) == 0) {
            for (int i = 0; i < fim_report.count; i++) {
                if (strcmp(fim_report.changes[i].status, "modified") == 0) {
                    fprintf(stdout, "FIM: %s modified - hash changed\n",
                            fim_report.changes[i].path);
                }
            }
            fim_free_report(&fim_report);
        }

        if (sca_run(&sca_report) == 0) {
            fprintf(stdout, "SCA scan: %d passed, %d failed out of %d\n",
                    sca_report.passed, sca_report.failed, sca_report.total);
            sca_free_report(&sca_report);
        }

        if (vuln_scan(&vuln_report) == 0) {
            fprintf(stdout, "Vuln scan: %d potential vulnerabilities found\n",
                    vuln_report.count);
            vuln_free_report(&vuln_report);
        }

        sleep(60);
    }

    fprintf(stderr, "TRAKSHYA System Monitor shutting down...\n");
    return 0;
}