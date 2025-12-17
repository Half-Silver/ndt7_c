/*
 * Test program for NDT7 C library
 * Compile with: gcc -o test_ndt7 test_ndt7.c -I./include -L./build -lndt7_c -lssl -lcrypto -pthread
 * Run with: ./test_ndt7 [hostname]
 */

#include "ndt7/ndt7.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global variable to store the last test results
static ndt7_summary last_results;
static int test_complete = 0;

// Logging callbacks
static void log_info(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) printf("[INFO] %s\n", msg);
}

static void log_warning(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) fprintf(stderr, "[WARN] %s\n", msg);
}

// Test completion callback
static void on_test_complete(void *user_data, const ndt7_summary *summary) {
    (void)user_data;
    if (summary) {
        memcpy(&last_results, summary, sizeof(ndt7_summary));
        test_complete = 1;
    }
}

// Print test results
static void print_results(const ndt7_summary *results) {
    if (!results) return;
    
    printf("\n=== Network Test Results ===\n");
    printf("Server: %s\n", results->server_hostname);
    printf("Location: %s\n", results->server_location);
    printf("Timestamp: %llu\n", (unsigned long long)results->timestamp_sec);
    printf("\n");
    
    printf("=== Performance Metrics ===\n");
    printf("Download Speed:   %8.2f Mbps\n", results->download_speed_kbit / 1000.0);
    printf("Upload Speed:     %8.2f Mbps\n", results->upload_speed_kbit / 1000.0);
    printf("Latency:          %8.2f ms\n", results->latency_ms);
    printf("Jitter:           %8.2f μs\n", results->jitter_us);
    printf("Packet Loss:      %8.2f %%\n", results->packet_loss_percent);
    printf("Min RTT:          %8d μs\n", results->min_rtt_usec);
    printf("Download Retrans: %8.2f %%\n", results->download_retrans * 100);
    printf("Upload Retrans:   %8.2f %%\n", results->upload_retrans * 100);
    
    printf("\n=== Quality Scores (0-100) ===\n");
    printf("Video Streaming:  %8d\n", results->video_streaming_score);
    printf("Online Gaming:    %8d\n", results->online_gaming_score);
    printf("Video Chatting:   %8d\n", results->video_chatting_score);
}

int main(int argc, char *argv[]) {
    ndt7_settings settings;
    ndt7_logger logger;
    
    // Initialize with defaults
    ndt7_settings_init(&settings);
    
    // Configure server (use command line arg or default)
    if (argc > 1) {
        settings.hostname = argv[1];
    } else {
        // Default to Cloudflare's speed test server
        settings.hostname = "speed.cloudflare.com";
        printf("No hostname specified, using default: %s\n", settings.hostname);
    }
    
    // Configure test parameters
    settings.port = "443";
    settings.scheme = "wss";
    settings.run_download = 1;  // Enable download test
    settings.run_upload = 1;    // Enable upload test
    settings.timeout_sec = 30;  // 30 second timeout
    settings.max_runtime_sec = 120; // Max 2 minutes per test
    
    // Set up logging
    logger.user_data = NULL;
    logger.info = log_info;
    logger.warning = log_warning;
    logger.debug = NULL;
    
    printf("Starting network test to %s...\n", settings.hostname);
    printf("This may take a few minutes to complete...\n\n");
    
    // Run the test
    test_complete = 0;
    ndt7_error err = ndt7_run(&settings, &logger, &last_results);
    
    if (err != NDT7_OK) {
        fprintf(stderr, "Test failed with error: %d\n", err);
        return EXIT_FAILURE;
    }
    
    // Print results
    print_results(&last_results);
    
    // Output results as JSON
    char json[4096];
    if (ndt7_summary_to_json(&last_results, json, sizeof(json)) > 0) {
        printf("\n=== JSON Output ===\n%s\n", json);
    } else {
        printf("\nFailed to generate JSON output\n");
    }
    
    return EXIT_SUCCESS;
}
