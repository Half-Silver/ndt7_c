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
    
    /* Configure server - use locate API for automatic discovery */
    if (argc > 1) {
        settings.hostname = argv[1];
        printf("Using specified NDT7 server: %s (will use locate API for discovery)\n", settings.hostname);
    } else {
        /* Use locate API for automatic server discovery */
        settings.hostname = NULL;  /* Let locate API find nearest server */
        printf("Using M-Lab locate API to find nearest NDT7 server...\n");
    }
    
    settings.port = "443";
    settings.scheme = "wss";
    settings.run_download = 1;
    settings.run_upload = 0;
    
    /* Optional: Add client metadata as query parameters */
    settings.query_params = "client_library=ndt7-c-client&client_version=1.0";
    
    /* Set up logger */
    logger.user_data = NULL;
    logger.info = log_info;
    logger.warning = log_warning;
    logger.debug = log_info;  /* Enable debug logging */
    
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
    printf("Packet Loss: %.2f%%\n", summary.packet_loss_percent);
    printf("Min RTT:  %u µs\n", summary.min_rtt_usec);
    
    /* Print network quality scores */
    printf("\n=== Network Quality ===\n");
    printf("Video Streaming:  %u/100 (%s)\n", 
           summary.video_streaming_score, 
           summary.video_streaming_score >= 80 ? "Great" : 
           summary.video_streaming_score >= 60 ? "Good" :
           summary.video_streaming_score >= 40 ? "Fair" : "Poor");
    printf("Online Gaming:    %u/100 (%s)\n", 
           summary.online_gaming_score,
           summary.online_gaming_score >= 80 ? "Great" : 
           summary.online_gaming_score >= 60 ? "Good" :
           summary.online_gaming_score >= 40 ? "Fair" : "Poor");
    printf("Video Chatting:    %u/100 (%s)\n", 
           summary.video_chatting_score,
           summary.video_chatting_score >= 80 ? "Great" : 
           summary.video_chatting_score >= 60 ? "Good" :
           summary.video_chatting_score >= 40 ? "Fair" : "Poor");
    
    /* Output JSON */
    printf("\n=== JSON Output ===\n");
    char json[4096];
    if (ndt7_summary_to_json(&summary, json, sizeof(json)) > 0) {
        printf("%s\n", json);
    }
    
    return EXIT_SUCCESS;
}

