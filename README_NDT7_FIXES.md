# NDT7 Library Fixes

## Summary of Fixes Applied

The NDT7 C library has been updated to comply with the official NDT7 specification (v0.10.0).

### 1. WebSocket Handshake Fixes
- **Proper Key Generation**: Now generates random 16-byte WebSocket keys using OpenSSL's RAND_bytes
- **Base64 Encoding**: Proper base64 encoding of keys and accept values
- **Validation**: Validates server's Sec-WebSocket-Accept response against expected value
- **User-Agent**: Added proper User-Agent header

### 2. Protocol Compliance
- **Correct URLs**: Uses proper NDT7 endpoints `/ndt/v7/download` and `/ndt/v7/upload`
- **Subprotocol**: Uses required `net.measurementlab.ndt.v7` WebSocket subprotocol
- **Query Parameters**: Supports client metadata via query string parameters

### 3. JSON Parsing Improvements
- **TCPInfo Parsing**: Extracts all TCPInfo fields (MinRTT, RTT, BytesRetrans, etc.)
- **AppInfo Parsing**: Parses application-level measurements for speed calculations
- **Packet Loss**: Calculates packet loss from BytesRetrans/BytesSent ratio

### 4. Server Compatibility

#### Cloudflare Speed Test
Cloudflare's `speed.cloudflare.com` does NOT implement the NDT7 protocol. It uses a proprietary protocol. The NDT7 library will return "404 Not Found" when trying to connect to Cloudflare.

#### M-Lab Servers
M-Lab servers now require access tokens for authentication. Use the locate service to get authenticated URLs:
```bash
curl -s https://locate.measurementlab.net/v2/nearest/ndt/ndt7 | jq -r '.results[0].urls."wss:///ndt/v7/download"'
```

#### Working Server Configuration
```c
/* Use authenticated URL from locate service */
settings.download_url = "wss://server.example.com/ndt/v7/download?access_token=TOKEN";

/* Or configure hostname manually (may not work without auth) */
settings.hostname = "ndt-server.example.com";
settings.query_params = "client_library=ndt7-c-client&client_version=1.0";
```

## Usage

### Basic Example
```c
#include "ndt7/ndt7.h"

ndt7_settings settings;
ndt7_summary summary;
ndt7_logger logger = {0};

ndt7_settings_init(&settings);
settings.hostname = "your-ndt7-server.com";
settings.run_download = 1;

ndt7_error err = ndt7_run(&settings, &logger, &summary);
if (err == NDT7_OK) {
    printf("Download: %.2f Mbps\n", summary.download_speed_kbit / 1000.0);
    printf("Latency: %.2f ms\n", summary.latency_ms);
    printf("Packet Loss: %.2f%%\n", summary.packet_loss_percent);
}
```

### Compilation
```bash
gcc -o example example.c -I./include -L./build -lndt7_c $(pkg-config --cflags --libs openssl) -pthread
```

## Testing

The fixed library has been tested and successfully:
- Connects to servers using proper WebSocket handshake
- Parses JSON measurement messages
- Calculates network metrics
- Generates compliant output

## Integration with ALLmark

To integrate with the ALLmark project:
1. Copy the fixed library (`src/ndt7.c`, `include/ndt7/ndt7.h`) to the ALLmark project
2. Update the network_test.c to use the NDT7 library for packet loss measurement
3. Configure with appropriate NDT7 server or use locate service for dynamic server selection

## Notes

- The library is now fully NDT7 v0.10.0 compliant
- Server authentication may be required for production use
- Consider implementing the locate service API for automatic server discovery
- The library provides network quality scores suitable for different use cases (video streaming, gaming, video chat)
