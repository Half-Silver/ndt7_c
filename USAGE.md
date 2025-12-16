# How to Use NDT7 C Library in Your Custom Program

## Method 1: Using CMake (Recommended)

### Step 1: Add the library to your CMake project

If you've installed the library system-wide:
```cmake
cmake_minimum_required(VERSION 3.12)
project(my_ndt7_app)

find_package(OpenSSL REQUIRED)

# Find the library
find_library(NDT7_C_LIB ndt7_c PATHS /usr/local/lib)
find_path(NDT7_C_INCLUDE ndt7/ndt7.h PATHS /usr/local/include)

if(NDT7_C_LIB AND NDT7_C_INCLUDE)
    include_directories(${NDT7_C_INCLUDE})
    add_executable(my_app main.c)
    target_link_libraries(my_app ${NDT7_C_LIB} OpenSSL::SSL OpenSSL::Crypto)
else()
    message(FATAL_ERROR "ndt7_c library not found")
endif()
```

### Step 2: Or add as a subdirectory

If you have the ndt7_c source in your project:
```cmake
cmake_minimum_required(VERSION 3.12)
project(my_ndt7_app)

add_subdirectory(path/to/ndt7_c)

find_package(OpenSSL REQUIRED)

add_executable(my_app main.c)
target_link_libraries(my_app ndt7_c OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(my_app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/path/to/ndt7_c/include)
```

## Method 2: Manual Compilation

### Step 1: Compile your program

```bash
gcc -o my_app my_app.c \
    -I/path/to/ndt7_c/include \
    -L/path/to/ndt7_c/build \
    -lndt7_c \
    -lssl -lcrypto \
    -pthread
```

Or if the library is installed system-wide:
```bash
gcc -o my_app my_app.c -lndt7_c -lssl -lcrypto -pthread
```

## Complete Example Program

Create a file `my_app.c`:

```c
#include "ndt7/ndt7.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Custom logger functions */
static void my_log_info(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) {
        fprintf(stdout, "[INFO] %s\n", msg);
    }
}

static void my_log_warning(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) {
        fprintf(stderr, "[WARNING] %s\n", msg);
    }
}

static void my_log_debug(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) {
        fprintf(stdout, "[DEBUG] %s\n", msg);
    }
}

int main(int argc, char *argv[]) {
    ndt7_settings settings;
    ndt7_summary summary;
    ndt7_logger logger;
    
    /* Initialize settings with defaults */
    ndt7_settings_init(&settings);
    
    /* Configure test settings */
    if (argc > 1) {
        settings.hostname = argv[1];  /* Use hostname from command line */
    } else {
        /* Use default or set your preferred server */
        settings.hostname = "ndt7-mlab1-xxx.measurementlab.net";
    }
    
    settings.port = "443";
    settings.scheme = "wss";           /* Use secure WebSocket */
    settings.run_download = 1;         /* Run download test */
    settings.run_upload = 0;           /* Skip upload test for now */
    settings.timeout_sec = 7;          /* 7 second timeout */
    settings.max_runtime_sec = 14;     /* Max 14 seconds per test */
    settings.summary_only = 0;         /* Show progress messages */
    
    /* Set up logger */
    logger.user_data = NULL;
    logger.info = my_log_info;
    logger.warning = my_log_warning;
    logger.debug = my_log_debug;
    
    /* Run the NDT7 test */
    printf("Starting NDT7 speed test...\n");
    ndt7_error err = ndt7_run(&settings, &logger, &summary);
    
    if (err != NDT7_OK) {
        fprintf(stderr, "NDT7 test failed with error code: %d\n", (int)err);
        return EXIT_FAILURE;
    }
    
    /* Print results in human-readable format */
    printf("\n=== Test Results ===\n");
    printf("Download Speed: %.2f Mbps (%.2f kbit/s)\n",
           summary.download_speed_kbit / 1000.0,
           summary.download_speed_kbit);
    
    if (summary.upload_speed_kbit > 0.0) {
        printf("Upload Speed:   %.2f Mbps (%.2f kbit/s)\n",
               summary.upload_speed_kbit / 1000.0,
               summary.upload_speed_kbit);
    }
    
    printf("Latency:        %.2f ms\n", summary.latency_ms);
    printf("Jitter:         %.2f µs (%.4f ms)\n",
           summary.jitter_us, summary.jitter_us / 1000.0);
    printf("Packet Loss:    %.2f%%\n", summary.packet_loss_percent);
    printf("Min RTT:        %u µs\n", summary.min_rtt_usec);
    
    if (summary.server_hostname[0]) {
        printf("Server:         %s\n", summary.server_hostname);
    }
    
    /* Generate and print JSON output */
    printf("\n=== JSON Output ===\n");
    char json_buf[4096];
    int json_len = ndt7_summary_to_json(&summary, json_buf, sizeof(json_buf));
    
    if (json_len > 0) {
        printf("%s\n", json_buf);
        
        /* You can also save to file */
        FILE *fp = fopen("ndt7_results.json", "w");
        if (fp) {
            fprintf(fp, "%s\n", json_buf);
            fclose(fp);
            printf("\nResults saved to ndt7_results.json\n");
        }
    } else {
        fprintf(stderr, "Failed to generate JSON output\n");
    }
    
    /* Print quality scores */
    printf("\n=== Network Quality ===\n");
    printf("Video Streaming: %u/100 (%s)\n",
           summary.video_streaming_score,
           summary.video_streaming_score >= 80 ? "Great" :
           summary.video_streaming_score >= 60 ? "Good" :
           summary.video_streaming_score >= 40 ? "Fair" : "Poor");
    
    printf("Online Gaming:   %u/100 (%s)\n",
           summary.online_gaming_score,
           summary.online_gaming_score >= 80 ? "Great" :
           summary.online_gaming_score >= 60 ? "Good" :
           summary.online_gaming_score >= 40 ? "Fair" : "Poor");
    
    printf("Video Chatting:  %u/100 (%s)\n",
           summary.video_chatting_score,
           summary.video_chatting_score >= 80 ? "Great" :
           summary.video_chatting_score >= 60 ? "Good" :
           summary.video_chatting_score >= 40 ? "Fair" : "Poor");
    
    return EXIT_SUCCESS;
}
```

## Minimal Example (JSON Only)

If you just want JSON output for integration:

```c
#include "ndt7/ndt7.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    ndt7_settings settings;
    ndt7_summary summary;
    ndt7_logger logger = {0};  /* Use default logger */
    
    ndt7_settings_init(&settings);
    settings.hostname = "your-server.measurementlab.net";
    settings.run_download = 1;
    
    if (ndt7_run(&settings, &logger, &summary) == NDT7_OK) {
        char json[4096];
        if (ndt7_summary_to_json(&summary, json, sizeof(json)) > 0) {
            printf("%s\n", json);
        }
    }
    
    return 0;
}
```

## Using in a Snap Package

### snapcraft.yaml example:

```yaml
name: my-benchmark
version: '1.0'
summary: Network benchmark using NDT7
description: |
  A network benchmark tool that uses NDT7 for speed testing.

grade: stable
confinement: strict

parts:
  ndt7-lib:
    source: https://github.com/yourusername/ndt7_c.git
    plugin: cmake
    build-packages:
      - libssl-dev
    stage-packages:
      - libssl3
      - libcrypto3
  
  my-app:
    source: .
    plugin: cmake
    build-packages:
      - libssl-dev
    stage-packages:
      - libssl3
      - libcrypto3
    cmake-parameters:
      - -DCMAKE_PREFIX_PATH=$SNAPCRAFT_STAGE

apps:
  my-benchmark:
    command: my-app
    plugs:
      - network
```

## API Quick Reference

### Initialize Settings
```c
ndt7_settings settings;
ndt7_settings_init(&settings);
settings.hostname = "server.example.com";
settings.run_download = 1;
```

### Set Up Logger (Optional)
```c
ndt7_logger logger = {
    .user_data = NULL,
    .info = my_info_callback,
    .warning = my_warning_callback,
    .debug = my_debug_callback  /* Can be NULL */
};
```

### Run Test
```c
ndt7_summary summary;
ndt7_error err = ndt7_run(&settings, &logger, &summary);
if (err != NDT7_OK) {
    /* Handle error */
}
```

### Get JSON Output
```c
char json[4096];
int len = ndt7_summary_to_json(&summary, json, sizeof(json));
if (len > 0) {
    /* Use json string */
}
```

## Error Handling

```c
ndt7_error err = ndt7_run(&settings, &logger, &summary);

switch (err) {
    case NDT7_OK:
        printf("Test completed successfully\n");
        break;
    case NDT7_ERR_INVALID_ARGUMENT:
        fprintf(stderr, "Invalid settings\n");
        break;
    case NDT7_ERR_NETWORK:
        fprintf(stderr, "Network error occurred\n");
        break;
    case NDT7_ERR_PROTOCOL:
        fprintf(stderr, "Protocol error (WebSocket/TLS)\n");
        break;
    case NDT7_ERR_INTERNAL:
        fprintf(stderr, "Internal error\n");
        break;
    default:
        fprintf(stderr, "Unknown error: %d\n", err);
        break;
}
```

## Tips

1. **Always check return values** - The library returns `NDT7_OK` on success
2. **Use logger callbacks** - They help debug connection issues
3. **Set appropriate timeouts** - Default is 7 seconds, adjust based on your network
4. **JSON buffer size** - Use at least 4096 bytes for JSON output
5. **Thread safety** - The library is not thread-safe; use one instance per thread

## Troubleshooting

### "Library not found" error
- Make sure you've installed the library: `cmake --install build`
- Or specify the path with `-L/path/to/lib` and `-I/path/to/include`

### OpenSSL errors
- Install OpenSSL development packages: `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (RHEL/CentOS)

### Connection failures
- Check firewall settings
- Verify server hostname and port
- Use `logger.debug` to see detailed connection logs

