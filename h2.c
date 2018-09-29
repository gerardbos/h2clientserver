#include "h2.h"

#include <string.h>
#include "log.h"

#include <nghttp2/nghttp2.h>

#define H2_SEND_BLOCK_SIZE	1024

static const char * TAG = "h2";

// string to default h2 (https) port
const char h2_default_port[] = "443";

// http status strings
const char h2_http_status_200[4] = "200";
const char h2_http_status_400[4] = "400";
const char h2_http_status_403[4] = "403";
const char h2_http_status_404[4] = "404";
const char h2_http_status_405[4] = "405";
const char h2_http_status_408[4] = "408";

// protocol const declarations
const char h2_header_path[] = ":path";
const char h2_header_method[] = ":method";
const char h2_header_scheme[] = ":scheme";
const char h2_header_authority[] = ":authority";
const char h2_header_status[] = ":status";
const char h2_header_contenttype[] = "content-type";
const char h2_header_cachecontrol[] = "cache-control";

const char h2_header_common_contenttype_json[] = "application/json";
const char h2_header_common_contenttype_html[] = "text/html";
const char h2_header_common_contenttype_text[] = "text/plain";
const char h2_header_common_cachecontrol_nocache[] = "no-cache";

static const char h2_method_get[] = "GET";
static const char h2_method_put[] = "PUT";
static const char h2_method_post[] = "POST";

/**
 * Get the string representation of method m
 * @param m The method type
 * @return String, NULL if invalid type.
 */
const char * h2_method_to_string(enum h2_method m)
{
	const char * r = NULL;
	switch(m){
		case H2_GET:
			r = h2_method_get;
			break;
		case H2_PUT:
			r = h2_method_put;
			break;
		case H2_POST:
			r = h2_method_post;
			break;
		default:
			break;
	}
	return r;
}

/**
 * Convert http method string to enum
 * @param m The method string
 * @param length The length of the string, if 0, then strlen is used.
 * @return enum h2_method
 */
enum h2_method h2_method_from_string(const char * method, unsigned int length)
{
	if(length == 0){
		length = strlen(method);
	}

	if(length == h2_const_strlen(h2_method_get) && memcmp(h2_method_get, method, h2_const_strlen(h2_method_get)) == 0){
		return H2_GET;
	}

	if(length == h2_const_strlen(h2_method_put) && memcmp(h2_method_put, method, h2_const_strlen(h2_method_put)) == 0){
		return H2_PUT;
	}

	if(length == h2_const_strlen(h2_method_post) && memcmp(h2_method_post, method, h2_const_strlen(h2_method_post)) == 0){
		return H2_POST;
	}

	return H2_METHOD_UNKNOWN;
}

const char * h2_http_status_to_string(enum h2_http_status s)
{
	const char * r = NULL;
	switch(s){
		case H2_OK:
			r = h2_http_status_200;
			break;
		case H2_BAD_REQUEST:
			r = h2_http_status_400;
			break;
		case H2_FORBIDEN:
			r = h2_http_status_403;
			break;
		case H2_NOT_FOUND:
			r = h2_http_status_404;
			break;
		case H2_METHOD_NOT_ALLOWED:
			r = h2_http_status_405;
			break;
		case H2_REQUEST_TIMEOUT:
			r = h2_http_status_408;
			break;
		default:
			break;
	}

	return r;
}

/**
 * Receive the data from the server
 * @param user_data A pointer to the h2client_connection_handle structure
 */
ssize_t h2_nghttp2_callback_recv(nghttp2_session * session, uint8_t * buf, size_t length, int flags, void * user_data)
{
	struct h2_connection * connection = user_data;
	int copied_bytes = SSL_read(connection->ssl, buf, (int)length);

	if(copied_bytes < 0){
		int err = SSL_get_error(connection->ssl, copied_bytes);

		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
			return NGHTTP2_ERR_WOULDBLOCK;

		log(INFO, TAG, "Connection %d: SSL_read error %d", connection->id, err);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}else if(copied_bytes == 0){
		log(INFO, TAG, "Connection %d: read EOF", connection->id);
		return NGHTTP2_ERR_EOF;
	}

	return copied_bytes;
}

/**
 * Send data to the receiving end
 * @param session
 * @param data
 * @param length
 * @param flags
 * @param user_data A pointer to the h2client_connection_handle structure
 */
ssize_t h2_nghttp2_callback_send(nghttp2_session * session, const uint8_t * data, size_t length, int flags, void * user_data)
{
	int copied_bytes = 0;
	struct h2_connection * connection = user_data;

	while(copied_bytes < length){
		int chunk_size =
			(length - copied_bytes) > H2_SEND_BLOCK_SIZE?H2_SEND_BLOCK_SIZE:(length - copied_bytes);
		int copied_tmp = SSL_write(connection->ssl, data + copied_bytes, chunk_size);
		if(copied_tmp <= 0){
			int err = SSL_get_error(connection->ssl, copied_tmp);

			if(copied_bytes > 0){
				return copied_bytes;
			}

			if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
				return NGHTTP2_ERR_WOULDBLOCK;

			log(INFO, TAG, "Connection %d: SSL_write error %d", connection->id, err);
			return  NGHTTP2_ERR_CALLBACK_FAILURE;
		}else{
			copied_bytes += copied_tmp;
		}
	}

	return copied_bytes;

}
