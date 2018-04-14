#include "h2.h"

#include <string.h>

static const char * h2_default_port = "443";

/**
 * Get the string representation of method m
 * @param m The method type
 * @return String, NULL if invalid type.
 */
const char * h2_method_to_string(enum h2_method m)
{
	char * r = NULL;
	switch(m){
		case H2_GET:
			r = "GET";
			break;
		case H2_PUT:
			r = "PUT";
			break;
		case H2_POST:
			r = "POST";
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
