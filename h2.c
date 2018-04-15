#include "h2.h"

#include <string.h>
#include "h2log.h"

#include <nghttp2/nghttp2.h>

#define H2_SEND_BLOCK_SIZE	1024

static const char * TAG = "h2";

static const char h2_default_port[] = "443";

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
 * Split URL string into host as port. Does not do anything with the path
 * Note that no new memory is allocated, pointers in the url string are used instead,
 * so make sure the string keep to exist if the res is used.
 * @param url The url string
 * @param res Pointer where to store the result
 * @return true if parsing goes well, otherwise false
 */
bool h2_parse_url(const char * url, struct h2_parsed_url * output)
{
	// We only interested in https
	size_t len, i, offset, tmp_len;
	const char * tmp;

	len = strlen(url);
	if(len < 9 || memcmp("https://", url, 8) != 0){
		return false;
	}
	// set protocol
	output->protocol = url;
	output->protocol_length = 5;

	offset = 8;
	tmp = &(url[offset]);
	tmp_len = 0;
	if (url[offset] == '['){
		// IPv6 literal address
		offset++;
		tmp++;
		for(i = offset; i < len; i++){
			if (url[i] == ']'){
				tmp_len = i - offset;
				offset = i + 1;
				break;
			}
		}
	} else {
		// IPv4 or hostname
		const char delims[] = ":/?#";
		for(i = offset; i < len; i++){
			if(strchr(delims, url[i]) != NULL){
				break;
			}
		}
		tmp_len = i - offset;
		offset = i;
	}
	if(tmp_len == 0){
		return false;
	}
	// set host
	output->host = tmp;
	output->host_length = tmp_len;

	tmp_len = 0;
	if(offset < len && url[offset] == ':') {
		// port
		const char delims[] = "/?#";
		offset++;
		tmp = &(url[offset]);
		for(i = offset; i < len; i++){
			if(strchr(delims, url[i]) != NULL){
				// delimiter found
				break;
			}
			if(url[i] < '0' || url[i] > '9'){
				// Invalid characters in port
				return false;
			}
			if(i - offset > 4){
				// Port has more than 5 characters
				// this should not happen (2^16 max)
				return false;
			}
			if(i - offset == 4){
				// port should not be higher then 2^16 - 1 = 65535
				if(url[offset] > '6'){
					return false;
				}
				if(url[offset] == '6' && url[offset + 1] > '5'){
					return false;
				}
				if(url[offset] == '6' && url[offset + 1] == '5' && url[offset + 2] > '5'){
					return false;
				}
				if(url[offset] == '6' && url[offset + 1] == '5' && url[offset + 2] == '5' && url[offset + 3] > '3'){
					return false;
				}
				if(url[offset] == '6' && url[offset + 1] == '5' && url[offset + 2] == '5' && url[offset + 3] == '3' && url[offset + 4] > '5'){
					return false;
				}
			}
		}
		tmp_len = i - offset;
		if (tmp_len == 0) {
			return false;
		}
		offset = i;
	}else{
		// If no port has been set, assume https
		tmp = h2_default_port;
		tmp_len = 3;
	}
	// set port
	output->service = tmp;
	output->service_length = tmp_len;

	if(offset < len){
		// the url contains more than only the server address
		// TODO: we can also just return. Choices.
		return false;
	}
	return true;
}

/**
 * Receive the data from the server
 * @param session
 * @param buf
 * @param length
 * @param flags
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
 * @param user_data A pointer the the h2client_connection_handle structure
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
