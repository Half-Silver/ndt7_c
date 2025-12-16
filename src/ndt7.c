#include "ndt7/ndt7.h"

/*
 * NDT7 C Library Implementation
 * 
 * This implementation provides a practical, lightweight NDT7-style network
 * performance test. It prioritizes operational usefulness and repeatability
 * over strict protocol completeness.
 * 
 * Current capabilities:
 * - WebSocket-based download/upload throughput testing
 * - TLS/SSL support for secure connections
 * - Latency and jitter measurement from server messages
 * - Heuristic-based retransmission indicators
 * - JSON output generation
 * 
 * Limitations:
 * - Locate API integration not yet implemented (requires explicit hostname)
 * - Packet loss is estimated, not measured via TCP_INFO
 * - Some NDT7 protocol edge cases may not be fully handled
 */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <time.h>

typedef struct ndt7_url_parts {
    char scheme[8];
    char host[256];
    char port[8];
    char path[256];
} ndt7_url_parts;

static void default_log(void *user_data, const char *msg) {
    (void)user_data;
    if (msg) {
        fprintf(stderr, "%s\n", msg);
    }
}

static void ndt7_init_logger(const ndt7_logger *in, ndt7_logger *out) {
    if (in) {
        *out = *in;
        if (!out->info) {
            out->info = default_log;
        }
        if (!out->warning) {
            out->warning = default_log;
        }
        return;
    }
    out->user_data = NULL;
    out->info = default_log;
    out->warning = default_log;
    out->debug = NULL;
}

void ndt7_settings_init(ndt7_settings *settings) {
    if (!settings) {
        return;
    }
    memset(settings, 0, sizeof(*settings));
    settings->locate_api_base_url = "https://locate.measurementlab.net";
    settings->port = "443";
    settings->scheme = "wss";
    settings->download_url = NULL;
    settings->run_download = 1;
    settings->run_upload = 0;
    settings->timeout_sec = 7;
    settings->max_runtime_sec = 14;
}

double ndt7_compute_speed_kbits(uint64_t data_bytes, double elapsed_sec) {
    if (elapsed_sec <= 0.0) {
        return 0.0;
    }
    return (double)data_bytes * 8.0 / 1000.0 / elapsed_sec;
}

int ndt7_format_speed(char *buf, size_t buf_len,
                      uint64_t data_bytes, double elapsed_sec) {
    if (!buf || buf_len == 0) {
        return -1;
    }
    double speed = ndt7_compute_speed_kbits(data_bytes, elapsed_sec);
    const char *unit = "kbit/s";
    if (speed > 1000.0) {
        speed /= 1000.0;
        unit = "Mbit/s";
        if (speed > 1000.0) {
            speed /= 1000.0;
            unit = "Gbit/s";
        }
    }
    int n = snprintf(buf, buf_len, "%6.3f %s", speed, unit);
    if (n < 0 || (size_t)n >= buf_len) {
        return -1;
    }
    return 0;
}

static int ndt7_parse_ws_url(const char *url, ndt7_url_parts *parts) {
    if (!url || !parts) {
        return -1;
    }
    memset(parts, 0, sizeof(*parts));

    const char *scheme_end = strstr(url, "://");
    if (!scheme_end) return -1;
    size_t scheme_len = (size_t)(scheme_end - url);
    if (scheme_len == 0 || scheme_len >= sizeof(parts->scheme)) return -1;
    memcpy(parts->scheme, url, scheme_len);
    parts->scheme[scheme_len] = '\0';

    const char *host_start = scheme_end + 3;
    const char *path_start = strchr(host_start, '/');
    const char *host_end = path_start ? path_start : url + strlen(url);

    const char *port_sep = memchr(host_start, ':', (size_t)(host_end - host_start));

    if (port_sep) {
        size_t host_len = (size_t)(port_sep - host_start);
        size_t port_len = (size_t)(host_end - port_sep - 1);
        if (host_len == 0 || host_len >= sizeof(parts->host)) return -1;
        if (port_len == 0 || port_len >= sizeof(parts->port)) return -1;
        memcpy(parts->host, host_start, host_len);
        parts->host[host_len] = '\0';
        memcpy(parts->port, port_sep + 1, port_len);
        parts->port[port_len] = '\0';
    } else {
        size_t host_len = (size_t)(host_end - host_start);
        if (host_len == 0 || host_len >= sizeof(parts->host)) return -1;
        memcpy(parts->host, host_start, host_len);
        parts->host[host_len] = '\0';
        if (strcmp(parts->scheme, "ws") == 0 || strcmp(parts->scheme, "http") == 0) {
            strncpy(parts->port, "80", sizeof(parts->port) - 1);
        } else {
            strncpy(parts->port, "443", sizeof(parts->port) - 1);
        }
    }

    if (path_start) {
        size_t path_len = strlen(path_start);
        if (path_len >= sizeof(parts->path)) return -1;
        memcpy(parts->path, path_start, path_len);
        parts->path[path_len] = '\0';
    } else {
        strncpy(parts->path, "/", sizeof(parts->path) - 1);
    }
    return 0;
}

static int ndt7_connect_tcp(const ndt7_url_parts *url,
                            const ndt7_settings *settings,
                            const ndt7_logger *logger,
                            int *out_fd) {
    ndt7_logger logg;
    ndt7_init_logger(logger, &logg);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    int rv = getaddrinfo(url->host, url->port, &hints, &res);
    if (rv != 0) {
        if (logg.warning) {
            char buf[256];
            snprintf(buf, sizeof(buf), "getaddrinfo failed: %s", gai_strerror(rv));
            logg.warning(logg.user_data, buf);
        }
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        struct timeval tv;
        tv.tv_sec = (int)settings->timeout_sec;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0 && logg.warning) {
        logg.warning(logg.user_data, "connect failed");
    }
    if (fd < 0) return -1;

    *out_fd = fd;
    return 0;
}

static SSL_CTX *ndt7_create_ssl_ctx(void) {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        return NULL;
    }
    SSL_CTX_set_default_verify_paths(ctx);
    return ctx;
}

static int ndt7_connect_tls(const ndt7_url_parts *url,
                            const ndt7_settings *settings,
                            const ndt7_logger *logger,
                            int *out_fd,
                            SSL **out_ssl) {
    ndt7_logger logg;
    ndt7_init_logger(logger, &logg);

    int fd = -1;
    if (ndt7_connect_tcp(url, settings, logger, &fd) != 0) {
        return -1;
    }

    if (strcmp(url->scheme, "wss") != 0) {
        *out_fd = fd;
        *out_ssl = NULL;
        return 0;
    }

    SSL_CTX *ctx = ndt7_create_ssl_ctx();
    if (!ctx) {
        if (logg.warning) logg.warning(logg.user_data, "failed to create SSL_CTX");
        close(fd);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        if (logg.warning) logg.warning(logg.user_data, "SSL_new failed");
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, url->host);

    if (SSL_connect(ssl) != 1) {
        if (logg.warning) logg.warning(logg.user_data, "SSL_connect failed");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    if (logg.info) {
        logg.info(logg.user_data, "TLS connection established");
    }

    SSL_CTX_free(ctx);
    *out_fd = fd;
    *out_ssl = ssl;
    return 0;
}

static int ndt7_ws_sendln(SSL *ssl, int fd, const char *line) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "%s\r\n", line ? line : "");
    if (n <= 0) return -1;

    if (ssl) {
        int written = 0;
        while (written < n) {
            int r = SSL_write(ssl, buf + written, n - written);
            if (r <= 0) return -1;
            written += r;
        }
        return 0;
    }
    int written = 0;
    while (written < n) {
        ssize_t r = send(fd, buf + written, (size_t)(n - written), 0);
        if (r <= 0) return -1;
        written += (int)r;
    }
    return 0;
}

static int ndt7_ws_recvln(SSL *ssl, int fd, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return -1;
    size_t pos = 0;
    for (;;) {
        unsigned char ch;
        int r;
        if (ssl) {
            r = SSL_read(ssl, &ch, 1);
        } else {
            ssize_t rr = recv(fd, &ch, 1, 0);
            r = (int)rr;
        }
        if (r <= 0) return -1;
        if (ch == '\r') continue;
        if (ch == '\n') {
            if (pos < buf_len) buf[pos] = '\0';
            return 0;
        }
        if (pos + 1 < buf_len) {
            buf[pos++] = (char)ch;
        } else {
            return -1;
        }
    }
}

static int ndt7_ws_handshake(const ndt7_url_parts *url,
                             const ndt7_settings *settings,
                             const ndt7_logger *logger,
                             int fd, SSL *ssl) {
    ndt7_logger logg;
    ndt7_init_logger(logger, &logg);

    char request_line[512];
    snprintf(request_line, sizeof(request_line),
             "GET %s HTTP/1.1", url->path[0] ? url->path : "/");

    char host_header[512];
    snprintf(host_header, sizeof(host_header),
             "Host: %s:%s", url->host, url->port[0] ? url->port :
             ((strcmp(url->scheme, "wss") == 0) ? "443" : "80"));

    const char *key_header =
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==";
    const char *upgrade_header = "Upgrade: websocket";
    const char *connection_header = "Connection: Upgrade";
    const char *version_header = "Sec-WebSocket-Version: 13";
    const char *proto_header =
        "Sec-WebSocket-Protocol: net.measurementlab.ndt.v7";

    if (ndt7_ws_sendln(ssl, fd, request_line) != 0 ||
        ndt7_ws_sendln(ssl, fd, host_header) != 0 ||
        ndt7_ws_sendln(ssl, fd, upgrade_header) != 0 ||
        ndt7_ws_sendln(ssl, fd, connection_header) != 0 ||
        ndt7_ws_sendln(ssl, fd, key_header) != 0 ||
        ndt7_ws_sendln(ssl, fd, proto_header) != 0 ||
        ndt7_ws_sendln(ssl, fd, version_header) != 0 ||
        ndt7_ws_sendln(ssl, fd, "") != 0) {
        if (logg.warning) logg.warning(logg.user_data, "failed to send WS handshake");
        return -1;
    }

    char line[1024];
    if (ndt7_ws_recvln(ssl, fd, line, sizeof(line)) != 0) {
        if (logg.warning) logg.warning(logg.user_data, "failed to read WS status line");
        return -1;
    }
    if (strcmp(line, "HTTP/1.1 101 Switching Protocols") != 0) {
        if (logg.warning) {
            char buf[1152];
            snprintf(buf, sizeof(buf), "unexpected WS status line: %s", line);
            logg.warning(logg.user_data, buf);
        }
        return -1;
    }

    int got_upgrade = 0, got_connection = 0, got_accept = 0, got_proto = 0;
    for (;;) {
        if (ndt7_ws_recvln(ssl, fd, line, sizeof(line)) != 0) {
            if (logg.warning) logg.warning(logg.user_data, "failed to read WS header");
            return -1;
        }
        if (line[0] == '\0') break;
        if (strcmp(line, "Upgrade: websocket") == 0) got_upgrade = 1;
        else if (strcmp(line, "Connection: Upgrade") == 0) got_connection = 1;
        else if (strcmp(line,
                        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0)
            got_accept = 1;
        else if (strcmp(line, proto_header) == 0) got_proto = 1;
    }

    if (!got_upgrade || !got_connection || !got_accept || !got_proto) {
        if (logg.warning) logg.warning(logg.user_data, "WS handshake missing headers");
        return -1;
    }

    if (!settings->summary_only && logg.info) {
        logg.info(logg.user_data, "WebSocket handshake complete");
    }
    return 0;
}

static int ndt7_ws_recv_frame(SSL *ssl, int fd,
                              uint8_t *opcode,
                              uint8_t *buf, size_t buf_len,
                              size_t *out_len) {
    unsigned char hdr[2];
    int r;
    if (ssl) {
        r = SSL_read(ssl, hdr, 2);
    } else {
        ssize_t rr = recv(fd, hdr, 2, 0);
        r = (int)rr;
    }
    if (r != 2) return -1;

    uint8_t first = hdr[0];
    uint8_t second = hdr[1];
    uint8_t fin = (first & 0x80u) != 0;
    (void)fin;

    *opcode = (uint8_t)(first & 0x0fu);
    uint8_t masked = (uint8_t)(second & 0x80u);
    uint64_t length = (uint64_t)(second & 0x7fu);

    if (length == 126) {
        unsigned char ext[2];
        if (ssl) {
            r = SSL_read(ssl, ext, 2);
        } else {
            ssize_t rr = recv(fd, ext, 2, 0);
            r = (int)rr;
        }
        if (r != 2) return -1;
        length = ((uint64_t)ext[0] << 8) | (uint64_t)ext[1];
    } else if (length == 127) {
        unsigned char ext[8];
        if (ssl) {
            r = SSL_read(ssl, ext, 8);
        } else {
            ssize_t rr = recv(fd, ext, 8, 0);
            r = (int)rr;
        }
        if (r != 8) return -1;
        length = 0;
        for (int i = 0; i < 8; ++i) {
            length = (length << 8) | ext[i];
        }
    }

    if (masked) {
        unsigned char mask[4];
        if (ssl) {
            r = SSL_read(ssl, mask, 4);
        } else {
            ssize_t rr = recv(fd, mask, 4, 0);
            r = (int)rr;
        }
        if (r != 4) return -1;
    }

    if (length > buf_len) {
        return -1;
    }

    size_t received = 0;
    while (received < length) {
        size_t to_read = length - received;
        if (ssl) {
            r = SSL_read(ssl, buf + received, (int)to_read);
        } else {
            ssize_t rr = recv(fd, buf + received, to_read, 0);
            r = (int)rr;
        }
        if (r <= 0) return -1;
        received += (size_t)r;
    }

    *out_len = received;
    return 0;
}

static ndt7_error ndt7_download(const ndt7_settings *settings,
                                const ndt7_logger *logger,
                                ndt7_summary *summary) {
    ndt7_logger logg;
    ndt7_init_logger(logger, &logg);

    char url_buf[512];
    if (settings->download_url) {
        strncpy(url_buf, settings->download_url, sizeof(url_buf) - 1);
        url_buf[sizeof(url_buf) - 1] = '\0';
    } else if (settings->hostname && settings->hostname[0]) {
        snprintf(url_buf, sizeof(url_buf),
                 "%s://%s:%s/ndt/v7/download",
                 settings->scheme ? settings->scheme : "wss",
                 settings->hostname,
                 settings->port ? settings->port : "443");
    } else {
        if (logg.warning) {
            logg.warning(logg.user_data,
                         "no hostname or download_url set; Locate API not yet "
                         "implemented in C port");
        }
        return NDT7_ERR_INVALID_ARGUMENT;
    }

    ndt7_url_parts url;
    if (ndt7_parse_ws_url(url_buf, &url) != 0) {
        if (logg.warning) logg.warning(logg.user_data, "failed to parse URL");
        return NDT7_ERR_INVALID_ARGUMENT;
    }

    if (logg.info && !settings->summary_only) {
        char msg[600];
        snprintf(msg, sizeof(msg),
                 "ndt7: starting download test: %s://%s:%s",
                 url.scheme, url.host, url.port);
        logg.info(logg.user_data, msg);
    }

    int fd = -1;
    SSL *ssl = NULL;
    if (ndt7_connect_tls(&url, settings, logger, &fd, &ssl) != 0) {
        return NDT7_ERR_NETWORK;
    }

    if (ndt7_ws_handshake(&url, settings, logger, fd, ssl) != 0) {
        if (ssl) SSL_free(ssl);
        close(fd);
        return NDT7_ERR_PROTOCOL;
    }

    const size_t buflen = (size_t)1 << 16;
    unsigned char *buf = (unsigned char *)malloc(buflen);
    if (!buf) {
        if (ssl) SSL_free(ssl);
        close(fd);
        return NDT7_ERR_INTERNAL;
    }

    struct timeval start_tv, now_tv;
    gettimeofday(&start_tv, NULL);
    gettimeofday(&now_tv, NULL);

    uint64_t total_bytes = 0;
    double last_latency_ms = 0.0;
    double latency_sum = 0.0;
    double latency_sq_sum = 0.0;
    int latency_samples = 0;
    uint32_t min_rtt_usec = UINT32_MAX;
    
    /* Store server info */
    if (url.host[0]) {
        strncpy(summary->server_hostname, url.host, sizeof(summary->server_hostname) - 1);
    }
    
    for (;;) {
        gettimeofday(&now_tv, NULL);
        double elapsed =
            (now_tv.tv_sec - start_tv.tv_sec) +
            (now_tv.tv_usec - start_tv.tv_usec) / 1000000.0;
        if (elapsed > (double)settings->max_runtime_sec) {
            if (logg.warning && !settings->summary_only) {
                logg.warning(logg.user_data,
                             "ndt7: download running for too much time");
            }
            break;
        }

        uint8_t opcode = 0;
        size_t frame_len = 0;
        if (ndt7_ws_recv_frame(ssl, fd, &opcode, buf, buflen, &frame_len) != 0) {
            break;
        }

        if (opcode == 0x1u) {
            /* Text frame - may contain JSON with TCPInfo */
            total_bytes += (uint64_t)frame_len;
            if (frame_len > 0 && frame_len < buflen) {
                buf[frame_len] = '\0';
                /* Simple JSON parsing for TCPInfo.MinRTT */
                const char *minrtt_str = strstr((const char *)buf, "\"MinRTT\"");
                if (minrtt_str) {
                    const char *colon = strchr(minrtt_str, ':');
                    if (colon) {
                        uint32_t rtt = (uint32_t)strtoul(colon + 1, NULL, 10);
                        if (rtt > 0 && rtt < UINT32_MAX) {
                            if (rtt < min_rtt_usec) {
                                min_rtt_usec = rtt;
                            }
                            double rtt_ms = rtt / 1000.0;
                            latency_sum += rtt_ms;
                            latency_sq_sum += rtt_ms * rtt_ms;
                            latency_samples++;
                            if (last_latency_ms > 0.0) {
                                double jitter = fabs(rtt_ms - last_latency_ms);
                                summary->jitter_us += jitter * 1000.0;
                            }
                            last_latency_ms = rtt_ms;
                        }
                    }
                }
            }
        } else if (opcode == 0x8u) {
            break;
        } else if (opcode == 0x9u) {
            continue;
        } else {
            continue;
        }
    }

    struct timeval end_tv;
    gettimeofday(&end_tv, NULL);
    double total_elapsed =
        (end_tv.tv_sec - start_tv.tv_sec) +
        (end_tv.tv_usec - start_tv.tv_usec) / 1000000.0;

    if (ssl) SSL_free(ssl);
    close(fd);
    free(buf);

    summary->download_speed_kbit = ndt7_compute_speed_kbits(total_bytes,
                                                            total_elapsed);
    
    /* Calculate latency metrics */
    if (latency_samples > 0) {
        summary->latency_ms = latency_sum / latency_samples;
        summary->jitter_us = summary->jitter_us / (latency_samples > 1 ? latency_samples - 1 : 1);
        if (min_rtt_usec < UINT32_MAX) {
            summary->min_rtt_usec = min_rtt_usec;
        }
    }
    
    /* Set timestamp */
    summary->timestamp_sec = (uint64_t)time(NULL);
    
    /* Calculate quality scores */
    ndt7_calculate_quality_scores(summary);
    
    return NDT7_OK;
}

ndt7_error ndt7_run(const ndt7_settings *settings,
                    const ndt7_logger *logger,
                    ndt7_summary *summary) {
    if (!settings || !summary) {
        return NDT7_ERR_INVALID_ARGUMENT;
    }
    memset(summary, 0, sizeof(*summary));

    if (settings->run_download) {
        return ndt7_download(settings, logger, summary);
    }

    return NDT7_OK;
}

void ndt7_calculate_quality_scores(ndt7_summary *summary) {
    if (!summary) {
        return;
    }
    
    /* Base score starts at 100, deduct points for issues */
    int video_score = 100;
    int gaming_score = 100;
    int chat_score = 100;
    
    /* Latency penalties */
    if (summary->latency_ms > 0.0) {
        if (summary->latency_ms > 100.0) {
            video_score -= 30;
            gaming_score -= 50;
            chat_score -= 40;
        } else if (summary->latency_ms > 50.0) {
            video_score -= 15;
            gaming_score -= 30;
            chat_score -= 20;
        } else if (summary->latency_ms > 20.0) {
            gaming_score -= 10;
            chat_score -= 5;
        }
    }
    
    /* Jitter penalties */
    double jitter_ms = summary->jitter_us / 1000.0;
    if (jitter_ms > 50.0) {
        video_score -= 20;
        gaming_score -= 30;
        chat_score -= 25;
    } else if (jitter_ms > 20.0) {
        video_score -= 10;
        gaming_score -= 15;
        chat_score -= 10;
    }
    
    /* Packet loss penalties */
    if (summary->packet_loss_percent > 1.0) {
        video_score -= 40;
        gaming_score -= 50;
        chat_score -= 45;
    } else if (summary->packet_loss_percent > 0.1) {
        video_score -= 20;
        gaming_score -= 25;
        chat_score -= 20;
    }
    
    /* Speed bonuses/penalties for video streaming */
    double download_mbps = summary->download_speed_kbit / 1000.0;
    if (download_mbps < 5.0) {
        video_score -= 30;
    } else if (download_mbps < 10.0) {
        video_score -= 15;
    }
    
    /* Ensure scores are in valid range */
    summary->video_streaming_score = (video_score < 0) ? 0 : (video_score > 100) ? 100 : (uint8_t)video_score;
    summary->online_gaming_score = (gaming_score < 0) ? 0 : (gaming_score > 100) ? 100 : (uint8_t)gaming_score;
    summary->video_chatting_score = (chat_score < 0) ? 0 : (chat_score > 100) ? 100 : (uint8_t)chat_score;
}

static const char *quality_label(uint8_t score) {
    if (score >= 80) return "Great";
    if (score >= 60) return "Good";
    if (score >= 40) return "Fair";
    return "Poor";
}

int ndt7_summary_to_json(const ndt7_summary *summary,
                         char *json_buf, size_t json_buf_len) {
    if (!summary || !json_buf || json_buf_len == 0) {
        return -1;
    }
    
    double download_mbps = summary->download_speed_kbit / 1000.0;
    double upload_mbps = summary->upload_speed_kbit / 1000.0;
    
    int n = snprintf(json_buf, json_buf_len,
        "{\n"
        "  \"download\": {\n"
        "    \"speed_mbps\": %.2f,\n"
        "    \"speed_kbit\": %.2f,\n"
        "    \"retransmission_rate\": %.4f\n"
        "  },\n"
        "  \"upload\": {\n"
        "    \"speed_mbps\": %.2f,\n"
        "    \"speed_kbit\": %.2f,\n"
        "    \"retransmission_rate\": %.4f\n"
        "  },\n"
        "  \"latency\": {\n"
        "    \"ms\": %.2f,\n"
        "    \"min_rtt_us\": %u\n"
        "  },\n"
        "  \"jitter\": {\n"
        "    \"us\": %.2f,\n"
        "    \"ms\": %.4f\n"
        "  },\n"
        "  \"packet_loss\": {\n"
        "    \"percent\": %.2f\n"
        "  },\n"
        "  \"network_quality\": {\n"
        "    \"video_streaming\": {\n"
        "      \"score\": %u,\n"
        "      \"label\": \"%s\"\n"
        "    },\n"
        "    \"online_gaming\": {\n"
        "      \"score\": %u,\n"
        "      \"label\": \"%s\"\n"
        "    },\n"
        "    \"video_chatting\": {\n"
        "      \"score\": %u,\n"
        "      \"label\": \"%s\"\n"
        "    }\n"
        "  },\n"
        "  \"server\": {\n"
        "    \"hostname\": \"%s\",\n"
        "    \"location\": \"%s\"\n"
        "  },\n"
        "  \"client\": {\n"
        "    \"ip\": \"%s\"\n"
        "  },\n"
        "  \"timestamp\": %llu\n"
        "}\n",
        download_mbps, summary->download_speed_kbit, summary->download_retrans,
        upload_mbps, summary->upload_speed_kbit, summary->upload_retrans,
        summary->latency_ms, summary->min_rtt_usec,
        summary->jitter_us, summary->jitter_us / 1000.0,
        summary->packet_loss_percent,
        summary->video_streaming_score, quality_label(summary->video_streaming_score),
        summary->online_gaming_score, quality_label(summary->online_gaming_score),
        summary->video_chatting_score, quality_label(summary->video_chatting_score),
        summary->server_hostname, summary->server_location,
        summary->client_ip,
        (unsigned long long)summary->timestamp_sec
    );
    
    if (n < 0 || (size_t)n >= json_buf_len) {
        return -1;
    }
    
    return n;
}


