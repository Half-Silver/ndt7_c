#include "ndt7/ndt7.h"

#include <stdio.h>
#include <stdlib.h>

static void log_info(void *user_data, const char *msg) {
    (void)user_data;
    fprintf(stderr, "%s\n", msg ? msg : "(null)");
}

static void log_warning(void *user_data, const char *msg) {
    (void)user_data;
    fprintf(stderr, "WARNING: %s\n", msg ? msg : "(null)");
}

int main(void) {
    ndt7_settings settings;
    ndt7_summary summary;
    ndt7_logger logger;

    ndt7_settings_init(&settings);

    logger.user_data = NULL;
    logger.info = log_info;
    logger.warning = log_warning;
    logger.debug = NULL;

    ndt7_error err = ndt7_run(&settings, &logger, &summary);
    if (err != NDT7_OK) {
        fprintf(stderr, "ndt7_run failed with error code %d\n", (int)err);
        return EXIT_FAILURE;
    }

    /* Output comprehensive JSON matching Cloudflare Speed Test format */
    char json_buf[4096];
    int json_len = ndt7_summary_to_json(&summary, json_buf, sizeof(json_buf));
    if (json_len > 0) {
        fprintf(stdout, "%s", json_buf);
    } else {
        fprintf(stderr, "Failed to generate JSON output\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


