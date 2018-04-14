#ifndef __H2SERVER_H__

#define __H2SERVER_H__

#include "h2.h"

struct h2server_handle{
	void * handle;
};

struct h2server_endpoint{
	char * path;
	enum h2_method method;
	void (* callback)(void);
};

int h2server_initialize(void);

struct h2server_handle * h2server_start(unsigned int port);
int h2server_register_endpoint(struct h2server_handle * handle, struct h2server_endpoint * endpoint);


#endif /* end of include guard: __H2_SERVER_H__ */
