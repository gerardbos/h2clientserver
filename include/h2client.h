#ifndef __H2CLIENT_H__

#define __H2CLIENT_H__

#include "h2.h"

#include <stddef.h>
#include <stdbool.h>

#define h2client_request_initialize()	{ \
	.method = H2_GET, \
	.server_url = NULL, \
	.path = NULL, \
	.requestbody.method = H2_HANDLEBODY_NONE, \
	.requestbody.body = NULL, \
	.requestbody.size = 0, \
	.requestbody.content_type = NULL, \
	.requestbody.callback = NULL, \
	.responsebody.method = H2_HANDLEBODY_NONE, \
	.responsebody.buffer = NULL, \
	.responsebody.buffer_size = 0, \
	.responsebody.size = 0, \
	.responsebody.callback = NULL \
}

#define h2client_do_request_simple(r_method, r_server_url, r_path)	{ \
	struct h2client_request r = h2client_request_initialize(); \
	r.method = r_method; \
	r.server_url = r_server_url; \
	r.path = r_path; \
	h2client_do_request(&r); \
}

struct h2client_requestbody {
	enum h2_handlebody_method method;
	const char * body;
	unsigned int size;
	unsigned int written;
	char * content_type;
	int (* callback)(char * buf, size_t len, bool * finished);
};

struct h2client_responsebody {
	enum h2_handlebody_method method;
	char * buffer;
	unsigned int buffer_size;
	unsigned int size;
	void (* callback)(const char * data, size_t len);
};

struct h2client_request{
	enum h2_method method;
	const char * server_url;
	const char * path;
	struct h2client_requestbody requestbody;
	struct h2client_responsebody responsebody;
	int status;
};

int h2client_initialize(void);
void h2client_deinitialize(void);
bool h2client_do_request(struct h2client_request * request);
bool h2client_disconnect(const char * protocol, const char * host, const char * service);

#endif /* end of include guard: __H2CLIENT_H__ */
