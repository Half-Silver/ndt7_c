/* Simple example program using the NDT7 C library
 * 
 * Compile with:
 *   gcc -o example example.c -I./include -L./build -lndt7_c -lssl -lcrypto -pthread
 * 
 * Or if library is installed:
 *   gcc -o example example.c -lndt7_c -lssl -lcrypto -pthread
 * 
 * Run with:
 *   ./example [hostname]
 */

#include "ndt7/ndt7.h"
#include <stdio.h>
#include <stdlib.h>

static void log_info(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) fprintf(stdout, "[INFO] %s\n", msg);
}

static void log_warning(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) fprintf(stderr, "[WARN] %s\n", msg);
}

int main(int argc, char *argv[]) {
    ndt7_settings settings;
    ndt7_summary summary;
    ndt7_logger logger;
    
    /* Initialize with defaults */
    ndt7_settings_init(&settings);
    
    /* Configure server (use command line arg or default) */
    if (argc > 1) {
        settings.hostname = argv[1];
    } else {
        /* You can set a default server here */
        settings.hostname = NULL;  /* Will need to set download_url or use Locate API */
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        fprintf(stderr, "Example: %s ndt7-mlab1-xxx.measurementlab.net\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    settings.port = "443";
    settings.scheme = "wss";
    settings.run_download = 1;
    settings.run_upload = 0;
    
    /* Set up logger */
    logger.user_data = NULL;
    logger.info = log_info;
    logger.warning = log_warning;
    logger.debug = NULL;
    
    /* Run the test */
    printf("Running NDT7 speed test on %s...\n\n", settings.hostname);
    ndt7_error err = ndt7_run(&settings, &logger, &summary);
    
    if (err != NDT7_OK) {
        fprintf(stderr, "Test failed with error: %d\n", err);
        return EXIT_FAILURE;
    }
    
    /* Print results */
    printf("\n=== Results ===\n");
    printf("Download: %.2f Mbps\n", summary.download_speed_kbit / 1000.0);
    printf("Latency:  %.2f ms\n", summary.latency_ms);
    printf("Jitter:   %.2f µs\n", summary.jitter_us);
    
    /* Output JSON */
    printf("\n=== JSON Output ===\n");
    char json[4096];
    if (ndt7_summary_to_json(&summary, json, sizeof(json)) > 0) {
        printf("%s\n", json);
    }
    
    return EXIT_SUCCESS;
}

