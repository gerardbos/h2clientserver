#ifndef __H2_H__

#define __H2_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define H2_ERROR_OK				0
#define H2_ERROR_INVALID_ARGUMENT		-1
#define H2_ERROR_NO_MEM				-2
#define H2_ERROR_STORAGE			-3
#define H2_ERROR_NO_NETWORK			-4

#define H2_ERROR_UNKNOWN			-128

#define H2_FLAG_NONE				(0x0)
#define H2_FLAG_RECEIVE_FRAME_COMPLETE		(0x1 << 0)
#define H2_FLAG_STREAM_CLOSE			(0x1 << 1)

enum h2_method {
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
	H2_NOT_FOUND	= 404
};

struct h2_parsed_url{
	const char * protocol;
	unsigned int protocol_length;
	const char * host;
	unsigned int host_length;
	const char * service;
	unsigned int service_length;
};

const char * h2_method_to_string(enum h2_method m);
bool h2_parse_url(const char * url, struct h2_parsed_url * output);

#endif /* end of include guard: __H2_H__ */
