# NDT7 C Library

A lightweight, pure-C network performance testing library inspired by the NDT7 protocol. Designed for embedded systems, Ubuntu Core, edge nodes, and environments where C++ or heavyweight runtimes are impractical.

**Metric calculations prioritize repeatability and operational usefulness over strict protocol completeness.**

## Design Goals & Non-Goals

### Design Goals
- **Minimal dependencies**: C, OpenSSL, WebSocket only
- **Deterministic runtime behavior**: Predictable, time-bounded tests
- **JSON-first output**: Structured data for automation and integration
- **Edge-safe and snap-friendly**: Suitable for Ubuntu Core and embedded Linux
- **Practical network quality measurement**: Reasonable approximation of user-perceived network performance
- **Lightweight and embeddable**: Single binary, no heavy runtime dependencies

### Non-Goals
- **Full protocol parity** with ndt7-client-cc or official NDT7 specification
- **Regulatory or compliance-grade benchmarking**: Not intended for official speed test certification
- **Kernel-level TCP instrumentation**: Does not use TCP_INFO for packet-level metrics
- **One-to-one Cloudflare metric matching**: Output format is inspired by, not guaranteed compatible with Cloudflare Speed Test
- **Complete Locate API integration**: Currently requires explicit server hostname (Locate API support is planned)

## Features

- **NDT7-Compatible WebSocket Tests**: Download and upload speed tests via WebSocket (TLS/SSL supported)
- **Comprehensive Metrics**: Collects download/upload speeds, latency, jitter, and retransmission indicators
- **JSON Output**: Generates structured JSON reports inspired by Cloudflare Speed Test format
- **Network Quality Scores**: Calculates quality scores for video streaming, online gaming, and video chatting
- **Lightweight C API**: Simple, easy-to-integrate C interface with minimal dependencies

## Building

### Requirements

- CMake 3.12 or later
- C compiler (C11 or later)
- OpenSSL development libraries
- libcurl (for future Locate API support)

### Build Instructions

```bash
cmake -S . -B build
cmake --build build
```

### Install

```bash
cmake --install build --prefix /usr/local
```

## Usage

**For detailed usage instructions and examples, see [USAGE.md](USAGE.md)**

### Quick Start

```c
#include "ndt7/ndt7.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    ndt7_settings settings;
    ndt7_summary summary;
    ndt7_logger logger;
    
    ndt7_settings_init(&settings);
    settings.hostname = "ndt7-mlab1-xxx.measurementlab.net";
    settings.port = "443";
    settings.scheme = "wss";
    settings.run_download = 1;
    
    logger.user_data = NULL;
    logger.info = my_log_info;
    logger.warning = my_log_warning;
    logger.debug = NULL;
    
    ndt7_error err = ndt7_run(&settings, &logger, &summary);
    if (err != NDT7_OK) {
        fprintf(stderr, "Test failed: %d\n", err);
        return EXIT_FAILURE;
    }
    
    /* Generate JSON output */
    char json_buf[4096];
    ndt7_summary_to_json(&summary, json_buf, sizeof(json_buf));
    printf("%s\n", json_buf);
    
    return EXIT_SUCCESS;
}
```

### JSON Output Format

The library generates comprehensive JSON output with a format inspired by Cloudflare Speed Test:

```json
{
  "download": {
    "speed_mbps": 89.50,
    "speed_kbit": 89500.00,
    "retransmission_rate": 0.0001
  },
  "upload": {
    "speed_mbps": 82.40,
    "speed_kbit": 82400.00,
    "retransmission_rate": 0.0002
  },
  "latency": {
    "ms": 3.85,
    "min_rtt_us": 3850
  },
  "jitter": {
    "us": 963.00,
    "ms": 0.963
  },
  "packet_loss": {
    "percent": 0.00
  },
  "network_quality": {
    "video_streaming": {
      "score": 95,
      "label": "Great"
    },
    "online_gaming": {
      "score": 92,
      "label": "Great"
    },
    "video_chatting": {
      "score": 94,
      "label": "Great"
    }
  },
  "server": {
    "hostname": "ndt7-mlab1-xxx.measurementlab.net",
    "location": "Kochi"
  },
  "client": {
    "ip": "103.189.143.33"
  },
  "timestamp": 1234567890
}
```

## API Reference

### Settings

```c
typedef struct ndt7_settings {
    const char *locate_api_base_url;  /* Locate API base URL */
    const char *hostname;              /* Server hostname (NULL for auto) */
    const char *port;                   /* Server port (e.g. "443") */
    const char *scheme;                 /* "ws" or "wss" */
    const char *download_url;           /* Full download URL (optional) */
    uint8_t run_download;               /* Enable download test */
    uint8_t run_upload;                 /* Enable upload test */
    uint32_t timeout_sec;               /* I/O timeout in seconds */
    uint32_t max_runtime_sec;           /* Max test runtime in seconds */
    uint8_t summary_only;               /* Hide per-interval logs */
} ndt7_settings;
```

### Summary

```c
typedef struct ndt7_summary {
    double download_speed_kbit;         /* Download speed in kbit/s */
    double upload_speed_kbit;            /* Upload speed in kbit/s */
    double latency_ms;                  /* Latency in milliseconds */
    double jitter_us;                    /* Jitter in microseconds */
    double packet_loss_percent;          /* Packet loss percentage */
    double download_retrans;             /* Download retransmission rate */
    double upload_retrans;                /* Upload retransmission rate */
    uint32_t min_rtt_usec;                /* Minimum RTT in microseconds */
    char server_location[128];          /* Server location */
    char server_hostname[256];            /* Server hostname */
    char client_ip[64];                  /* Client IP address */
    uint64_t timestamp_sec;                /* Test completion timestamp */
    uint8_t video_streaming_score;        /* Video streaming quality (0-100) */
    uint8_t online_gaming_score;          /* Online gaming quality (0-100) */
    uint8_t video_chatting_score;         /* Video chatting quality (0-100) */
} ndt7_summary;
```

### Functions

- `void ndt7_settings_init(ndt7_settings *settings)` - Initialize settings with defaults
- `ndt7_error ndt7_run(const ndt7_settings *settings, const ndt7_logger *logger, ndt7_summary *summary)` - Run NDT7 test
- `int ndt7_summary_to_json(const ndt7_summary *summary, char *json_buf, size_t json_buf_len)` - Generate JSON output
- `void ndt7_calculate_quality_scores(ndt7_summary *summary)` - Calculate network quality scores

## About This Library

This library implements an NDT7-style WebSocket throughput test optimized for practical network quality measurement. It is designed for lightweight, repeatable network quality assessment on Ubuntu Core devices and embedded systems, and is not intended as a full protocol-equivalent replacement for the official ndt7-client-cc.

**Use cases:**
- Edge node diagnostics and monitoring
- Ubuntu Core snap packages
- Embedded Linux network quality assessment
- IoT device network health checks
- Integration with monitoring systems (Grafana, Prometheus, etc.)

**Not suitable for:**
- Regulatory or compliance-grade speed testing
- Scientific benchmarking requiring kernel-level TCP metrics
- Applications requiring full NDT7 protocol compliance

## Integration with Snap Projects

This library is designed for use in Ubuntu Core snap packages. To use in your snap:

1. **Add to your snap's build dependencies**:
   ```yaml
   build-packages:
     - libssl-dev
     - libcurl4-openssl-dev
   ```

2. **Link against the library** in your snap's build:
   ```bash
   gcc -o myapp myapp.c -lndt7_c -lssl -lcrypto
   ```

3. **Use the JSON output** for integration with your testing pipeline:
   ```c
   char json[4096];
   ndt7_summary_to_json(&summary, json, sizeof(json));
   /* Send to your testing framework */
   ```

## License

BSD License (see LICENSE file)

## Contributing

Contributions welcome! This library is an ongoing effort to provide a practical, lightweight C implementation of NDT7-style network testing. 

**Current Status:**
- ✅ Basic download/upload throughput testing
- ✅ WebSocket with TLS support
- ✅ JSON output generation
- ✅ Network quality scoring
- ⚠️ Locate API integration (planned)
- ⚠️ Full protocol control message handling (partial)
- ⚠️ Kernel-level TCP metrics (heuristic-based)

When contributing, please note that this library prioritizes practical usability over strict protocol completeness. See the Design Goals & Non-Goals section above for scope guidance.

## Protocol Notes

This implementation provides a functional NDT7-style test that:
- Connects to NDT7 servers via WebSocket (ws/wss)
- Performs download and upload throughput measurements
- Extracts latency and jitter from server messages
- Calculates retransmission indicators from available data

It does not currently implement:
- Full NDT7 control protocol negotiation
- Official Measurement Lab Locate API integration
- Kernel-level TCP_INFO packet loss measurement
- All edge cases in the NDT7 specification

For full protocol compliance, consider using the official [ndt7-client-cc](https://github.com/m-lab/ndt7-client-cc) C++ implementation.

# ndt7_c
