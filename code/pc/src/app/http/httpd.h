/**
 * @file httpd.h
 * @brief Minimal HTTP server interface and protocol metadata.
 * @details
 * This module provides a lightweight HTTP service used to validate socket,
 * file-serving, and request parsing behavior in the network stack.
 */
#ifndef HTTPD_H
#define HTTPD_H

#include "net_err.h"
#include "net_plat.h"
#include "netapi.h"

#if 0 // For Windows host builds.
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#define HTTP_SIZE_METHOD            10      // Method token buffer size.
#define HTTP_SIZE_VERSION           10      // HTTP version buffer size.
#define HTTP_SIZE_URL               1024    // URL buffer size.

#define HTTP_SIZE_STATUS            5       // Status code buffer size.
#define HTTP_SIZE_REASON            10      // Reason phrase buffer size.

#define HTTPD_DEFAULT_ROOT          "htdocs"    // Default static file root.
#define HTTPD_DEFAULT_PORT          80          // Default listen port.
#define HTTPD_BACKLOG               5           // Pending accept queue length.
#define HTTPD_MAX_CLIENT            5           // Max concurrent client handlers.

/**
 * @brief File-extension to MIME-type mapping entry.
 */
typedef struct _http_mime_info_t {
    const char *extension;
    const char *type;
}http_mime_info_t;

/**
 * @brief Internal key for response/request property lookup.
 */
typedef enum _property_key_t {
    HTTP_PROPERTY_NONE = 0,
    HTTP_CONTENT_TYPE,
    HTTP_CONTENT_LENGTH,
    HTTP_CONNECTION,
}property_key_t;

/**
 * @brief Parsed HTTP header property.
 */
typedef struct _property_t {
    property_key_t key;
    char value[32];
}property_t;

/**
 * @brief Header name metadata used by parser/formatter helpers.
 */
typedef struct _property_info_t {
    const char * name;
}property_info_t;

/**
 * @brief Supported HTTP request methods.
 * @details
 * The current implementation focuses on GET to keep the test server small.
 */
typedef enum _http_method_t {
    HTTP_METHOD_GET,            // GET method.
}http_method_t;

/**
 * @brief Accepted client connection context.
 */
typedef struct _http_client_t {
	int sock;
	struct sockaddr_in addr;
    int len;
}http_client_t;

/**
 * @brief Parsed HTTP request line.
 */
typedef struct _http_request_t {
	char method[HTTP_SIZE_METHOD];      // Method token.
	char url[HTTP_SIZE_URL];            // Target URL path.
	char version[HTTP_SIZE_VERSION];    // HTTP version token.
}http_request_t;

#define HTTP_RESPONSE_PROPERTY_MAX      10

/**
 * @brief HTTP response metadata buffer.
 */
typedef struct _http_response_t {
    char version[HTTP_SIZE_VERSION];
    char status[HTTP_SIZE_STATUS];
    char reason[HTTP_SIZE_REASON];
	property_t property[HTTP_RESPONSE_PROPERTY_MAX];
}http_response_t;

/**
 * @brief Start the HTTP server.
 * @param[in] dir Static content root directory.
 * @param[in] port Listen port.
 * @return 0 on success, negative value on failure.
 */
int httpd_start (const char* dir, uint16_t port);

#endif // HTTPD_H
