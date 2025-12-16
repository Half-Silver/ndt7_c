#ifndef NDT7_C_NDT7_H
#define NDT7_C_NDT7_H

/**
 * @file ndt7.h
 * @brief NDT7-style network performance testing library (C implementation)
 * 
 * This library provides a lightweight, NDT7-inspired network performance testing
 * implementation optimized for embedded systems, Ubuntu Core, and edge nodes.
 * 
 * Metric calculations prioritize repeatability and operational usefulness
 * over strict protocol completeness.
 * 
 * @note This is not a full protocol-equivalent replacement for ndt7-client-cc.
 *       For full NDT7 protocol compliance, consider the official C++ implementation.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Feature flags - compile-time configuration */
#ifndef NDT7_HAS_LOCATE_API
#define NDT7_HAS_LOCATE_API 0  /* Locate API integration (planned) */
#endif

#ifndef NDT7_PROTOCOL_COMPLETE
#define NDT7_PROTOCOL_COMPLETE 0  /* Full protocol compliance (partial) */
#endif

typedef struct ndt7_settings {
    const char *locate_api_base_url; /* e.g. https://locate.measurementlab.net */
    const char *hostname;            /* optional static hostname, NULL for auto */
    const char *port;                /* e.g. "443" */
    const char *scheme;              /* "ws" or "wss" */

    /* Optional explicit ndt7 download URL (e.g. wss://host:443/ndt/v7/download).
       When non-NULL, this is used directly and Locate API is skipped. */
    const char *download_url;

    uint8_t run_download;            /* non-zero to run download test */
    uint8_t run_upload;              /* non-zero to run upload test */

    uint32_t timeout_sec;            /* IO timeout in seconds */
    uint32_t max_runtime_sec;        /* per-test max runtime */

    uint8_t summary_only;            /* hide per-interval logs when non-zero */
} ndt7_settings;

typedef struct ndt7_summary {
    /* Speed metrics */
    double download_speed_kbit;      /* Download speed in kbit/s */
    double upload_speed_kbit;         /* Upload speed in kbit/s */
    
    /* Network quality metrics */
    double latency_ms;                /* Latency in milliseconds */
    double jitter_us;                  /* Jitter in microseconds */
    double packet_loss_percent;        /* Packet loss percentage (0-100) */
    
    /* Retransmission rates */
    double download_retrans;          /* Download retransmission rate (0-1) */
    double upload_retrans;             /* Upload retransmission rate (0-1) */
    
    /* TCP metrics */
    uint32_t min_rtt_usec;             /* Minimum RTT in microseconds */
    
    /* Server information */
    char server_location[128];         /* Server location/city */
    char server_hostname[256];         /* Server hostname */
    char client_ip[64];                /* Client IP address */
    
    /* Timestamp */
    uint64_t timestamp_sec;            /* Unix timestamp when test completed */
    
    /* Network quality scores (0-100, higher is better) */
    uint8_t video_streaming_score;     /* Video streaming quality score */
    uint8_t online_gaming_score;       /* Online gaming quality score */
    uint8_t video_chatting_score;     /* Video chatting quality score */
} ndt7_summary;

typedef void (*ndt7_log_fn)(void *user_data, const char *msg);

typedef struct ndt7_logger {
    void *user_data;
    ndt7_log_fn info;
    ndt7_log_fn warning;
    ndt7_log_fn debug;
} ndt7_logger;

typedef enum ndt7_error {
    NDT7_OK = 0,
    NDT7_ERR_INVALID_ARGUMENT = 1,
    NDT7_ERR_NETWORK = 2,
    NDT7_ERR_PROTOCOL = 3,
    NDT7_ERR_INTERNAL = 4
} ndt7_error;

void ndt7_settings_init(ndt7_settings *settings);

ndt7_error ndt7_run(const ndt7_settings *settings,
                    const ndt7_logger *logger,
                    ndt7_summary *summary);

double ndt7_compute_speed_kbits(uint64_t data_bytes, double elapsed_sec);

int ndt7_format_speed(char *buf, size_t buf_len,
                      uint64_t data_bytes, double elapsed_sec);

/* JSON output functions */
/* Generate comprehensive JSON output matching Cloudflare Speed Test format.
   Returns number of bytes written, or -1 on error. */
int ndt7_summary_to_json(const ndt7_summary *summary,
                         char *json_buf, size_t json_buf_len);

/* Calculate network quality scores based on metrics */
void ndt7_calculate_quality_scores(ndt7_summary *summary);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NDT7_C_NDT7_H */


