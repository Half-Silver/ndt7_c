#include <stdio.h>
#include <string.h>
#include "include/ndt7/ndt7.h"

/* Test URL parsing function directly */
typedef struct ndt7_url_parts {
    char scheme[8];
    char host[256];
    char port[8];
    char path[256];
} ndt7_url_parts;

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
    
    /* Find the end of the path (before query string) */
    const char *query_start = NULL;
    if (path_start) {
        query_start = strchr(path_start, '?');
    }
    
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
        const char *path_end = query_start ? query_start : url + strlen(url);
        size_t path_len = (size_t)(path_end - path_start);
        if (path_len >= sizeof(parts->path)) return -1;
        memcpy(parts->path, path_start, path_len);
        parts->path[path_len] = '\0';
    } else {
        strncpy(parts->path, "/", sizeof(parts->path) - 1);
    }
    return 0;
}

int main() {
    /* Test URL from locate API */
    const char *test_url = "wss://ndt-ixe136308-6759e956.deenet.autojoin.measurement-lab.org/ndt/v7/download?access_token=eyJhbGciOiJFZERTQSIsImtpZCI6ImxvY2F0ZV8yMDIwMDQwOSJ9.eyJhdWQiOlsibmR0LWl4ZTEzNjMwOC02NzU5ZTk1Ni5kZWVuZXQuYXV0b2pvaW4ubWVhc3VyZW1lbnQtbGFiLm9yZyJdLCJleHAiOjE3NjU5NjkxNDcsImlzcyI6ImxvY2F0ZSIsImp0aSI6ImZkNTc5YjJmLWY4MTItNDNkNy05NjdlLWFlOTg5M2YyYzNkMyIsInN1YiI6Im5kdCJ9.hQoi7iuGK9reSpWigyik150yEUMWl9pha47Aa7fObHzl3r4CW7bjecUxQq_6y71G2p30kxjggvcGMx8y_oOLCA&index=0&locate_version=v2&metro_rank=0";
    
    printf("Testing URL parsing with:\n");
    printf("URL length: %zu\n", strlen(test_url));
    printf("URL: %.100s...\n\n", test_url);
    
    ndt7_url_parts parts;
    int result = ndt7_parse_ws_url(test_url, &parts);
    
    if (result == 0) {
        printf("URL parsing successful:\n");
        printf("  Scheme: %s\n", parts.scheme);
        printf("  Host: %s\n", parts.host);
        printf("  Port: %s\n", parts.port);
        printf("  Path: %s\n", parts.path);
    } else {
        printf("URL parsing failed with error: %d\n", result);
    }
    
    return 0;
}
