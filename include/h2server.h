#ifndef __H2SERVER_H__

#define __H2SERVER_H__

#include "h2.h"

struct h2server_handle{
	unsigned int port;
};

struct h2server_endpoint_header{
	const char * name;
	const char * value;
	struct h2server_endpoint_header * next;
};

struct h2server_endpoint{
	const char * path;
	enum h2_method method;
	struct h2server_endpoint_header * headers;
	int headers_count;
	void (* callback_request)(const char * buf, size_t len, bool finished, void ** private_data);
	int (* callback_response)(char * buf, size_t len, bool * finished, void ** private_data);
};

#define h2server_endpoint_initialize(path_, method_) {.path = path_, .method = method_, .headers = NULL, .headers_count = 0, .callback_request = NULL, .callback_response = NULL}
#define h2server_endpoint_add_header(endpoint_, header_) {(header_)->next = (endpoint_)->headers; (endpoint_)->headers = (header_); (endpoint_)->headers_count++;}

int h2server_initialize(const char * certificate, size_t certificate_len, const char * private_key, size_t private_key_len);

struct h2server_handle * h2server_start(unsigned int port);
bool h2server_stop(struct h2server_handle * handle);
bool h2server_register_endpoint(struct h2server_handle * handle_, struct h2server_endpoint * endpoint);


#endif /* end of include guard: __H2_SERVER_H__ */
