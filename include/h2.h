#ifndef __H2_H__

#define __H2_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/ssl.h>

#define H2_ERROR_OK				0
#define H2_ERROR_INVALID_ARGUMENT		-1
#define H2_ERROR_NO_MEM				-2
#define H2_ERROR_STORAGE			-3
#define H2_ERROR_NO_NETWORK			-4

#define H2_ERROR_UNKNOWN			-128

#define H2_FLAG_NONE				(0x0)
#define H2_FLAG_RECEIVE_FRAME_COMPLETE		(0x1 << 0)
#define H2_FLAG_STREAM_CLOSE			(0x1 << 1)

#define h2_const_strlen(h)			(sizeof(h) - 1)

// Create name value pairs where the value is not a string for nghttp2
#define h2_make_nv(name, namelen, value, valuelen) { \
	(uint8_t *)name, (uint8_t *)value, namelen, valuelen, NGHTTP2_NV_FLAG_NONE \
}

// Create name value pairs of strings for nghttp2. This only works with
// a char[], as sizeof is used to determine the values
#define h2_make_nv_short(name, value) { \
	(uint8_t *)name, (uint8_t *)value, sizeof(name) - 1, sizeof(value) - 1,	NGHTTP2_NV_FLAG_NONE \
}

// Assign name value pairs of strings for nghttp2
#define h2_assign_nv(ptr_, name_, namelen_, value_, valuelen_)  { \
	nghttp2_nv * ptr = ptr_; \
	(ptr)->name = (uint8_t *)name_; \
	(ptr)->value = (uint8_t *)value_; \
	(ptr)->namelen = namelen_; \
	(ptr)->valuelen = valuelen_; \
	(ptr)->flags = NGHTTP2_NV_FLAG_NONE; \
}

enum h2_method {
	H2_METHOD_UNKNOWN,
	H2_GET,
	H2_POST,
	H2_PUT
};

enum h2_handlebody_method {
	H2_HANDLEBODY_NONE,
	H2_HANDLEBODY_BUFFER,
	H2_HANDLEBODY_CALLBACK
};

enum h2_http_status {
	H2_OK 		= 200,
	H2_BAD_REQUEST	= 400,
	H2_FORBIDEN	= 403,
	H2_NOT_FOUND	= 404,
	H2_METHOD_NOT_ALLOWED = 405,
	H2_REQUEST_TIMEOUT = 408,
};

extern const char h2_default_port[4];

extern const char h2_http_status_200[4];
extern const char h2_http_status_400[4];
extern const char h2_http_status_403[4];
extern const char h2_http_status_404[4];
extern const char h2_http_status_405[4];
extern const char h2_http_status_408[4];

/**
 * This structure must be used as the first items of structures that are passed as user_data to the
 * nghttp2 callbacks (especially send_callback and recv_callback). So that these functions can be
 * shared over the client and server implementation
 */
struct h2_connection{
	unsigned int id;
	int sockfd;
	SSL * ssl;
};

// protocol const declarations
extern const char h2_header_path[6];
extern const char h2_header_method[8];
extern const char h2_header_scheme[8];
extern const char h2_header_authority[11];
extern const char h2_header_status[8];
extern const char h2_header_contenttype[13];
extern const char h2_header_cachecontrol[14];

extern const char h2_header_common_contenttype_json[17];
extern const char h2_header_common_contenttype_html[10];
extern const char h2_header_common_contenttype_text[11];
extern const char h2_header_common_cachecontrol_nocache[9];

const char * h2_method_to_string(enum h2_method m);
enum h2_method h2_method_from_string(const char * method, unsigned int length);
const char * h2_http_status_to_string(enum h2_http_status s);

#endif /* end of include guard: __H2_H__ */
