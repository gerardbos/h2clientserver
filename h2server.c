#include "h2server.h"

int h2server_initialize()
{
	return H2_ERROR_OK;
}

struct h2server_handle * h2server_start(unsigned int port)
{
	return NULL;
}

int h2server_register_endpoint(struct h2server_handle * handle, struct h2server_endpoint * endpoint)
{
	return H2_ERROR_UNKNOWN;
}
