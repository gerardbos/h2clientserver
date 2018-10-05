#include "h2client.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>

#include "log.h"

#define H2CLIENT_TASK_STACKSIZE		CONFIG_H2CLIENT_TASK_STACKSIZE // Stack size in words for the task (http_task) that handles a connection (>16KB required for mbedtls)
#define H2CLIENT_TASK_PRIORITY		5
#define H2CLIENT_REQUEST_QUEUE_LENGTH	5

#define H2CLIENT_TIMEOUT_REQUEST_MS	30000		// Timeout request for a http request to complete (needs to be longer then

#define H2CLIENT_TIMEOUT_ACQ_SEMAPHORE	500		// Timeout to wait for acquiring a lock to the connection bookkeeping

// Convert ms to ticks (round down)
#define ms_to_ticks(d_ms)		(TickType_t)(d_ms / portTICK_PERIOD_MS)

// Minimum calculation define
#define min(a, b)			(a < b?a:b)

// Initialize the request_internal structure
#define h2client_request_internal_initialize()	{ \
	.h2_stream_id = -1, \
	.error = false \
}

enum connection_state{
	CONN_EMPTY,
	CONN_CONFIGURED,
	CONN_CONNECTED
};

struct parsed_url{
	const char * protocol;
	unsigned int protocol_length;
	const char * host;
	unsigned int host_length;
	const char * service;
	unsigned int service_length;
	const char * path;
	unsigned int path_length;
};

struct server{
	char * protocol;
	char * host;
	char * service;
};

struct h2client_connection_handle{
	struct h2_connection conn;

	nghttp2_session * h2_session;

	enum connection_state state;
	struct server server;
	SemaphoreHandle_t semaphore;
	QueueHandle_t request_queue; // you can use this without acquiring a lock
	struct h2client_request_internal * current_request; // current active request
	uint64_t last_used; // last used
};

struct h2client_request_internal{
	struct h2client_request * original_request;
	int h2_stream_id;
	const char * path;
	SemaphoreHandle_t wait_semaphore;
#ifdef CONFIG_SUPPORT_STATIC_ALLOCATION
	StaticSemaphore_t wait_semaphore_store; // this way the semaphore is allocated on the stack, reducing memory fragmentation
#endif
	bool error;
};

// generic functions, divided over h2client and h2server (but not made externally available)
extern ssize_t h2_nghttp2_callback_recv(nghttp2_session * session, uint8_t * buf, size_t length, int flags, void * user_data);
extern ssize_t h2_nghttp2_callback_send(nghttp2_session * session, const uint8_t * data, size_t length, int flags, void * user_data);

// Local function definitions
static void task(void *args); // task function
static struct h2client_connection_handle * request_new_connection(const struct parsed_url * url);

// http2 actions
static bool request(struct h2client_connection_handle * handle, struct h2client_request_internal * request);

// connection functions
static bool connect_socket(struct server * url, int * fd);
static bool connect_ssl(struct h2client_connection_handle * handle);
static bool connect_h2(struct h2client_connection_handle * handle);

// handler function
static bool h2client_handle(struct h2client_connection_handle * handle);

// nghttp2 callback functions
static int callback_on_frame_recv(nghttp2_session * session, const nghttp2_frame * frame, void * user_data);
static int callback_on_data_chunk_recv(nghttp2_session * session, uint8_t flags, int32_t stream_id, const uint8_t * data, size_t len, void * user_data);
//static int callback_on_frame_send(nghttp2_session * session, const nghttp2_frame * frame, void * user_data);
static int callback_on_stream_close(nghttp2_session * session, int32_t stream_id, uint32_t error_code, void * user_data);
//static int callback_on_begin_headers(nghttp2_session * session, const nghttp2_frame * frame, void * user_data);
static int callback_on_header(nghttp2_session * session, const nghttp2_frame * frame, const uint8_t * name, size_t namelen, const uint8_t * value, size_t valuelen, uint8_t flags, void * user_data);

// Storage management functions
static struct h2client_connection_handle * get_store(const char * protocol, const char * host, const char * service);
static struct h2client_connection_handle * get_store_by_parsed_url(const struct parsed_url * url);
static struct h2client_connection_handle * get_empty_store();
static struct h2client_connection_handle * get_idle_store();
static void free_connection_handle(struct h2client_connection_handle * handle);

// Helper functions
bool parse_url(const char * url, struct parsed_url * output);

// handler functions for the response and request data
static ssize_t handle_request_data(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
static int handle_response_data(struct h2client_connection_handle * handle, const char * data, size_t len, int flags);

// Local const variables
static const char * TAG = "h2client";
static const char default_path[] = "/";

// Local variables
static TaskHandle_t task_handle;
static struct h2client_connection_handle connections[CONFIG_H2CLIENT_CONCURRENT_CONNECTIONS];
static volatile unsigned int new_connection_id = 0; // TODO: Add semaphore for this item (although it is only debugging, for now)
// This context handle can be used for multiple connection.
static SSL_CTX * ssl_ctx = NULL;
// The callbacks structure can be used to setup multiple session, it can also be created
// every time a session is created, but this pollutes the heap more (with the downside that this
// takes memory continuously)
static nghttp2_session_callbacks * nghttp2_callbacks = NULL;

/**
 * Initialize h2
 * @return H2_ERROR_OK if no error occurred, otherwise an H2_ERROR code
 */
int h2client_initialize()
{
	unsigned int i;

	// initialize SSL context used for all connection
	ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
	if(ssl_ctx == NULL){
		log(ERROR, TAG, "Cannot initialize ssl context");
		return H2_ERROR_NO_MEM;
	}else{
		// Tell SSL that we will support h2 protocol
		SSL_CTX_set_alpn_protos(ssl_ctx, (unsigned char *)NGHTTP2_PROTO_ALPN, NGHTTP2_PROTO_ALPN_LEN);
	}

	// initialize nghttp structures used for all connections
	nghttp2_session_callbacks_new(&nghttp2_callbacks);
	nghttp2_session_callbacks_set_send_callback(nghttp2_callbacks, h2_nghttp2_callback_send);
	nghttp2_session_callbacks_set_recv_callback(nghttp2_callbacks, h2_nghttp2_callback_recv);
	//nghttp2_session_callbacks_set_on_frame_send_callback(nghttp2_callbacks, callback_on_frame_send);
	nghttp2_session_callbacks_set_on_frame_recv_callback(nghttp2_callbacks, callback_on_frame_recv);
	nghttp2_session_callbacks_set_on_stream_close_callback(nghttp2_callbacks, callback_on_stream_close);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(nghttp2_callbacks, callback_on_data_chunk_recv);
	nghttp2_session_callbacks_set_on_header_callback(nghttp2_callbacks, callback_on_header);

	// initialize connection store
	memset(connections, 0, sizeof(connections));

	// Create connection queues and semaphores
	for(i = 0; i < (sizeof(connections) / sizeof(connections[0])); i++){
		struct h2client_connection_handle * handle = &(connections[i]);

		handle->request_queue = xQueueCreate(H2CLIENT_REQUEST_QUEUE_LENGTH, sizeof(struct h2client_request_internal *));
		if(handle->request_queue == NULL){
			// TODO: We need to cleanup properly
			return H2_ERROR_NO_MEM;
		}
		// set initial socket
		handle->conn.sockfd = -1;

		// set last_used to 0
		handle->last_used = 0;

		// TODO: Should we make this one static as well? It is only created on initialization, afterwards it is just re-used
		handle->semaphore = xSemaphoreCreateBinary();
		if(handle->semaphore == NULL){
			// TODO: We need to cleanup properly
			return H2_ERROR_NO_MEM;
		}
		xSemaphoreGive(handle->semaphore);
	}

	// Start h2_task
	if(xTaskCreate(task, "h2client_task", H2CLIENT_TASK_STACKSIZE, NULL, H2CLIENT_TASK_PRIORITY, &task_handle) != pdPASS){
		return H2_ERROR_NO_MEM;
	}

	return H2_ERROR_OK;
}

/**
 * Cleanup HTTP2 client
 */
void h2client_deinitialize(void)
{
	int i;

	for(i = 0; i < (sizeof(connections) / sizeof(connections[0])); i++){
		struct h2client_connection_handle * handle = &(connections[i]);

		if(xSemaphoreTake(connections[i].semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
			vQueueDelete(handle->request_queue);
			free_connection_handle(handle);

			vSemaphoreDelete(handle->semaphore);
		}
	}

	nghttp2_session_callbacks_del(nghttp2_callbacks);
	SSL_CTX_free(ssl_ctx);

	// TODO: Delete task properly
	vTaskDelete(task_handle);
}

/**
 * Perform a synchronous h2 request
 * @param request Pointer to the h2_request structure.
 * @return true if no error is detected during execution
 */
bool h2client_do_request(struct h2client_request * request)
{
	struct parsed_url url;

	if(!parse_url(request->url, &url)){
		log(ERROR, TAG, "Invalid server url: %s", request->url);
		return false;
	}

	// do request here
	struct h2client_connection_handle * handle = get_store_by_parsed_url(&url);
	if(handle == NULL){
		handle = request_new_connection(&url);
		if(handle == NULL){
			log(INFO, TAG, "Error setting up connection config for: %s", request->url);
			return false;
		}
	}else{
		log(INFO, TAG, "Reusing existing connection for: %s", request->url);
	}
	handle->last_used = esp_timer_get_time();

	struct h2client_request_internal r = h2client_request_internal_initialize();
	struct h2client_request_internal * r_ptr = &r;
	r.path = url.path;
	r.original_request = request;
	// create semaphore for wait
#ifdef CONFIG_SUPPORT_STATIC_ALLOCATION
	r.wait_semaphore = xSemaphoreCreateBinaryStatic(&(r.wait_semaphore_store));
#else
	r.wait_semaphore = xSemaphoreCreateBinary();
#endif
	if(r.wait_semaphore == NULL){
		log(ERROR, TAG, "Unable to create wait semaphore");
		return false;
	}

	if(xQueueSendToBack(handle->request_queue, &r_ptr, (TickType_t)0)){
		bool error = false;
		unsigned int timeout_ms = H2CLIENT_TIMEOUT_REQUEST_MS;
		if(request->timeout_ms > 0){
			timeout_ms = request->timeout_ms;
		}

		xSemaphoreGive(handle->semaphore);

		log(INFO, TAG, "Waiting for request to complete");

		if(xSemaphoreTake(r.wait_semaphore, ms_to_ticks(timeout_ms))){
			error = r.error;
			log(INFO, TAG, "Request complete");

			// Close request
			if(xSemaphoreTake(handle->semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
				handle->current_request = NULL;
				xSemaphoreGive(handle->semaphore);
			}else{
				log(ERROR, TAG, "Error acquiring lock to close request");
				// Force current request to NULL, otherwise, the next request would wait until timeout and cleanup connection
				handle->current_request = NULL;
			}
		}else{
			error = true;
			log(ERROR, TAG, "Waited too long for request to finish");

			if(xSemaphoreTake(handle->semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
				// Probably connection timeout (routing/server issues)
				// Cleanup connection to make place for next request
				free_connection_handle(handle);
				xSemaphoreGive(handle->semaphore);
			}else{
				log(ERROR, TAG, "Error acquiring lock to close timed out request");
			}
		}

		// Cleanup wait semaphore
		vSemaphoreDelete(r.wait_semaphore);
		return !error;
	}else{
		log(ERROR, TAG, "Queue full for connection: %s", request->url);
		xSemaphoreGive(handle->semaphore);
		return false;
	}
}

/**
 * Do a "forced" disconnect of the connection to server "server_url"
 * @param protocol The protocol string
 * @param host The host string
 * @param service The service of the connection (port)
 * @return true if disconnect was successful
 */
bool h2client_disconnect(const char * protocol, const char * host, const char * service)
{
	struct h2client_connection_handle * handle = get_store(protocol, host, service);
	if(handle != NULL){
		free_connection_handle(handle);
		return true;
	}
	xSemaphoreGive(handle->semaphore);
	return false;
}

/**
 * Internal functions
 */

/**
 * h2 connection and request handler task
 */
static void task(void *args)
{
	int i;
	while(true){
		for(i = 0; i < (sizeof(connections) / sizeof(connections[0])); i++){
			struct h2client_connection_handle * handle = &connections[i];

			if(xSemaphoreTake(handle->semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
				switch(handle->state){
					case CONN_CONFIGURED:
						// do connect
						{
							if(connect_socket(&handle->server, &handle->conn.sockfd) && connect_ssl(handle) && connect_h2(handle)){
								log(INFO, TAG, "Connection %u: Connected", handle->conn.id);
								handle->state = CONN_CONNECTED;
							}else{
								log(ERROR, TAG, "Connection %u: Error setting up socket (fd: %d) or SSL", handle->conn.id, handle->conn.sockfd);
								free_connection_handle(handle);
							}
						}
						break;
					case CONN_CONNECTED:
						// handle requests
						//log(INFO, TAG, "Connection %d: current_request: 0x%x", handle->id, (unsigned int)handle->current_request);
						if(handle->current_request != NULL){
							if(!h2client_handle(handle)){
								// Error in send or receive, close and cleanup connection
								log(ERROR, TAG, "Connection %u: Error in send or receive", handle->conn.id);
								free_connection_handle(handle);
							}
						}else{
							// Only get a new item from the queue if current_request == NULL
							// this ensures that we are not NULL-ing an in-progress connection.
							if(xQueueReceive(handle->request_queue, &(handle->current_request), 0)){
								// new item retrieved
								log(INFO, TAG, "Connection %u: [%s] %s",
										handle->conn.id,
										h2_method_to_string(handle->current_request->original_request->method),
										handle->current_request->path);

								// do GET, PUT or POST request
								request(handle, handle->current_request);
							}
						}
						break;
					case CONN_EMPTY:
						break;
					default:
						log(ERROR, TAG, "Connection %u: Unknown state (%d)", handle->conn.id, handle->state);
						break;
				}
				xSemaphoreGive(handle->semaphore);
			}else{
				log(ERROR, TAG, "Connection %u: Error obtaining semaphore", handle->conn.id);
			}
		}
		vTaskDelay(2);
	}
}

/**
 * Requests
 */

/**
 * Prepare and submit a request
 * @param handle The connection handle for this request
 * @param request The client request structure defining the request
 * @return true if the request was prepared and submitted without error.
 */
static bool request(struct h2client_connection_handle * handle, struct h2client_request_internal * request)
{
	const char * m = h2_method_to_string(request->original_request->method);
	int stream_id = -1;
	// make headers 1 item longer for the content type, if available
	unsigned int hdrs_items = 4;
	nghttp2_nv hdrs[5] = {
		h2_make_nv(h2_header_method, sizeof(h2_header_method) - 1, m, strlen(m)),
		h2_make_nv(h2_header_scheme, sizeof(h2_header_scheme) - 1, handle->server.protocol, strlen(handle->server.protocol)),
		h2_make_nv(h2_header_authority, sizeof(h2_header_authority) - 1, handle->server.host, strlen(handle->server.host)),
		h2_make_nv(h2_header_path, sizeof(h2_header_path) - 1, request->path, strlen(request->path))
	};

	if(request->original_request->requestbody.content_type != NULL){
		h2_assign_nv(&hdrs[hdrs_items++], h2_header_contenttype, sizeof(h2_header_contenttype) - 1, request->original_request->requestbody.content_type, strlen(request->original_request->requestbody.content_type));
	}

	if(request->original_request->method == H2_GET){
		stream_id = nghttp2_submit_request(handle->h2_session, NULL, hdrs, hdrs_items, NULL, NULL);
	}else if(request->original_request->method== H2_PUT || request->original_request->method == H2_POST){
		nghttp2_data_provider p;
		p.read_callback = handle_request_data;
		p.source.ptr = NULL; // not set, is already available in the handle->current_request (user_data)
		stream_id = nghttp2_submit_request(handle->h2_session, NULL, hdrs, hdrs_items, &p, NULL);
	}else{
		log(ERROR, TAG, "Connection %u: Unknown http2 method: %d", handle->conn.id, request->original_request->method);
	}

	if(stream_id < 0){
		log(ERROR, TAG, "Connection %u: Error prepping headers", handle->conn.id);
		return false;
	}

	log(INFO, TAG, "Connection %u: stream id %d", handle->conn.id, stream_id);
	handle->current_request->h2_stream_id = stream_id;
	return true;
}

/**
 * Connection functions
 */

/**
 * Setup the connection to the host
 * @param server The server as a struct (protocol://host[:port])
 * @param fd Pointer to place where to store the socket file descriptor
 * @return true if connection is made, otherwise false.
 */
static bool connect_socket(struct server * server, int * fd)
{
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	struct addrinfo * res;
	int r, sockfd;

	r = getaddrinfo(server->host, server->service, &hints, &res);
	if(r){
		log(ERROR, TAG, "getaddrinfo error: %d", r);
		goto err_addrinfo;
	}

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if(sockfd < 0){
		goto err_socket;
	}

	r = connect(sockfd, res->ai_addr, res->ai_addrlen);
	if(r < 0){
		goto err_connect;
	}

	freeaddrinfo(res);
	*fd = sockfd;
	return true;

err_connect:
	close(sockfd);
err_socket:
	freeaddrinfo(res);
err_addrinfo:
	return false;
}

/**
 * Setup SSL connection
 * Note that the sockfd of the handle should be set/connected
 * @param handle Connection handle
 * @return true if ssl negotiation is ok
 */
static bool connect_ssl(struct h2client_connection_handle * handle)
{
	int r, flags;

	handle->conn.ssl = SSL_new(ssl_ctx);
	if(handle->conn.ssl == NULL){
		return false;
	}

	SSL_set_tlsext_host_name(handle->conn.ssl, handle->server.host);
	SSL_set_fd(handle->conn.ssl, handle->conn.sockfd);
	r = SSL_connect(handle->conn.ssl);
	if(r < 1){
		int error = SSL_get_error(handle->conn.ssl, r);
		log(INFO, TAG, "Connection %u: SSL_connect() failed (return: %d, error: %d)", handle->conn.id, r, error);
		SSL_free(handle->conn.ssl);
		handle->conn.ssl = NULL;
		return false;
	}

	flags = fcntl(handle->conn.sockfd, F_GETFL, 0);
	fcntl(handle->conn.sockfd, F_SETFL, flags | O_NONBLOCK);

	return true;
}

/**
 * Setup http2 connection
 * @param handle Connection handle
 * @return true if SSL negotiation is OK
 */
static bool connect_h2(struct h2client_connection_handle * handle)
{
	if(nghttp2_session_client_new(&handle->h2_session, nghttp2_callbacks, handle) != 0){
		log(ERROR, TAG, "Connection %d: Unable to start new session", handle->conn.id);
		return false;
	}

	if(nghttp2_submit_settings(handle->h2_session, NGHTTP2_FLAG_NONE, NULL, 0) != 0){
		log(ERROR, TAG, "Connection %d: Error submitting session", handle->conn.id);
		nghttp2_session_del(handle->h2_session);
		return false;
	}

	return true;
}

/**
 * Handler functions
 */

/**
 * Handle h2 connection
 * @param handle
 * @return false if an error occurs
 */
static bool h2client_handle(struct h2client_connection_handle * handle)
{
	int r;

	if((r = nghttp2_session_send(handle->h2_session)) != 0){
		log(ERROR, TAG, "Connection %d: Send failed (error %d)", handle->conn.id, r);
		return false;
	}

	if((r = nghttp2_session_recv(handle->h2_session)) != 0){
		log(ERROR, TAG, "Connection %d: Receive failed (error %d)", handle->conn.id, r);
		return false;
	}
	return true;
}


/**
 * HTTP2 response data handler or callback wrapper (depending on how to handle the data)
 * @return This function shall return 0 (see nghttp2 documentation)
 */
static int handle_response_data(struct h2client_connection_handle * handle, const char * data, size_t length, int flags)
{
	if(length){
		log(DEBUG, TAG, "data received (%uB)", length);

		switch(handle->current_request->original_request->responsebody.method){
			case H2_HANDLEBODY_BUFFER:
				// Copy data to destination
				{
					struct h2client_responsebody * r = &handle->current_request->original_request->responsebody;
					int copy_bytes = min(r->buffer_size - r->size, length);

					if(copy_bytes < length){
						log(WARNING, TAG, "responsebody buffer full, skipping bytes");
					}

					if(copy_bytes > 0){
						memcpy(&(r->buffer[r->size]), data, copy_bytes);
						r->size += copy_bytes;
					}
				}
				break;
			case H2_HANDLEBODY_CALLBACK:
				handle->current_request->original_request->responsebody.callback(data, length);
				break;
			case H2_HANDLEBODY_NONE:
			default:
				break;
		}
	}

	if(flags & H2_FLAG_RECEIVE_FRAME_COMPLETE){
		//log(INFO, TAG, "frame completed");
	}
	if(flags & H2_FLAG_STREAM_CLOSE){
		//log(INFO, TAG, "stream closed");
		xSemaphoreGive(handle->current_request->wait_semaphore);
	}

	// should always return 0
	return 0;
}

/**
 * HTTP2 request data handler or callback wrapper (depending on how to handle the data)
 */
static ssize_t handle_request_data(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	int copied_bytes = 0;
	bool finished = false; // set to true to signal end of data

	struct h2client_connection_handle * handle = user_data;

	switch(handle->current_request->original_request->requestbody.method){
		case H2_HANDLEBODY_BUFFER:
			{
				struct h2client_requestbody * r = &handle->current_request->original_request->requestbody;
				copied_bytes = min(r->size, length);

				memcpy(buf, &(r->body[r->written]), copied_bytes);
				r->written += copied_bytes;

				finished = r->written >= r->size;
			}
			break;
		case H2_HANDLEBODY_CALLBACK:
			copied_bytes = handle->current_request->original_request->requestbody.callback((char *)buf, length, &finished);
			break;
		case H2_HANDLEBODY_NONE:
		default:
			finished = true;
			break;
	}

	if(finished){
		// No more request data
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	}

	return copied_bytes;
}

/**
 * nghttp2 callback functions
 */

/*
static int callback_on_frame_send(nghttp2_session * session, const nghttp2_frame * frame, void * user_data)
{
	struct h2client_connection_handle * handle = user_data;
	switch(frame->hd.type){
		case NGHTTP2_HEADERS:
			if(frame->headers.cat == NGHTTP2_HCAT_REQUEST && handle->current_request->h2_stream_id == frame->hd.stream_id){
				// All headers sent
			}
			break;
		default:
			break;
	}
	return 0;

}
*/

/**
 * Callback on a complete frame received
 * This function is used to finish up the response data retrieval
 */
static int callback_on_frame_recv(nghttp2_session * session, const nghttp2_frame * frame, void * user_data)
{
	struct h2client_connection_handle * handle = user_data;
	switch(frame->hd.type){
		case NGHTTP2_HEADERS:
			/*if(frame->headers.cat == NGHTTP2_HCAT_RESPONSE && handle->current_request->h2_stream_id == frame->hd.stream_id){
				// all headers received
			}*/
			break;
		case NGHTTP2_DATA:
			if(handle->current_request->h2_stream_id == frame->hd.stream_id){
				// Frame received
				return handle_response_data(handle, NULL, 0, H2_FLAG_RECEIVE_FRAME_COMPLETE);
			}
			break;
		default:
			break;
	}
	return 0;
}

/**
 * Callback on a retrieved data chunk
 * Used to handle response data
 */
static int callback_on_data_chunk_recv(nghttp2_session * session, uint8_t flags, int32_t stream_id, const uint8_t * data, size_t len, void * user_data)
{
	struct h2client_connection_handle * handle = user_data;

	if(handle->current_request->h2_stream_id == stream_id){
		return handle_response_data(handle, (char *)data, len, 0);
	}
	return 0;
}

/**
 * Callback on stream close
 * Used to mark the steam end
 */
static int callback_on_stream_close(nghttp2_session * session, int32_t stream_id, uint32_t error_code, void * user_data)
{
	struct h2client_connection_handle * handle = user_data;

	if(handle->current_request->h2_stream_id == stream_id){
		// Stream closed
		return handle_response_data(handle, NULL, 0, H2_FLAG_STREAM_CLOSE);
	}
	return 0;
}

/**
 * Callback on header
 */
static int callback_on_header(nghttp2_session * session, const nghttp2_frame * frame, const uint8_t * name, size_t namelen, const uint8_t * value, size_t valuelen, uint8_t flags, void * user_data)
{
	struct h2client_connection_handle * handle = user_data;
	switch(frame->hd.type){
		case NGHTTP2_HEADERS:
			if(frame->headers.cat == NGHTTP2_HCAT_RESPONSE && handle->current_request->h2_stream_id == frame->hd.stream_id){
				//log(INFO, TAG, "Response header: %s:%s", name, value);
				if(strncmp(h2_header_status, (char *)name, namelen) == 0){
					// status item
					int status = strtol((char *)value, NULL, 10);
					handle->current_request->original_request->status = status;
					log(INFO, TAG, "Status code: %d", status);
				}
			}
			break;
		default:
			break;
	}
	return 0;
}

/**
 * Storage management function
 */

/**
 * Request a new connection.
 * The real connection is created inside the h2client task()
 * @param url A parsed URL structure. Data from this structure is copied to the handle.
 * @return If new connection is configured, a pointer to the connection_handle (which is locked), if
 * 	the connection can not be configured, NULL is returned.
 */
static struct h2client_connection_handle * request_new_connection(const struct parsed_url * url)
{
	struct h2client_connection_handle * handle = get_empty_store();

	if(handle == NULL){
		// no empty store found, reuse oldest unused store
		handle = get_idle_store();
	}

	if(handle != NULL){
		// Empty handle found

		// Copy URL
		handle->server.protocol = malloc(url->protocol_length + 1);
		if(handle->server.protocol == NULL){
			xSemaphoreGive(handle->semaphore);
			return NULL;
		}
		handle->server.host = malloc(url->host_length + 1);
		if(handle->server.host == NULL){
			free(handle->server.protocol);
			xSemaphoreGive(handle->semaphore);
			return NULL;
		}
		handle->server.service = malloc(url->service_length + 1);
		if(handle->server.service == NULL){
			free(handle->server.protocol);
			free(handle->server.host);
			xSemaphoreGive(handle->semaphore);
			return NULL;
		}

		memcpy(handle->server.protocol, url->protocol, url->protocol_length);
		handle->server.protocol[url->protocol_length] = '\0';
		memcpy(handle->server.host, url->host, url->host_length);
		handle->server.host[url->host_length] = '\0';
		memcpy(handle->server.service, url->service, url->service_length);
		handle->server.service[url->service_length] = '\0';

		handle->conn.id = new_connection_id++;
		log(INFO, TAG, "Prepped connection: %s://%s:%s with ID: %u", handle->server.protocol, handle->server.host, handle->server.service, handle->conn.id);

		// Real connection is handled by h2_task
		handle->state = CONN_CONFIGURED;
	}else{
		log(ERROR, TAG, "No connection store available");
	}
	return handle;
}

/**
 * Get a connection handle.
 * If a proper handle is retrieved, it is locked, so make sure that you always give back the
 * semaphore after use!
 * @param protocol The protocol string
 * @param host The host string
 * @param service The service string
 * @return If a handle is found, a pointer to the connection_handle (which is locked), if
 * 	connection is not found, NULL is returned
 */
static struct h2client_connection_handle * get_store(const char * protocol, const char * host, const char * service)
{
	unsigned int i;
	for(i = 0; i < (sizeof(connections) / sizeof(connections[0])); i++){
		if(xSemaphoreTake(connections[i].semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
			if(connections[i].state != CONN_EMPTY){
				if(strcmp(connections[i].server.protocol, protocol) == 0
					&& strcmp(connections[i].server.host, host) == 0
					&& strcmp(connections[i].server.service, service) == 0){
					return &(connections[i]);
				}
			}
			xSemaphoreGive(connections[i].semaphore);
		}
	}
	return NULL;
}

/**
 * Get a connection handle.
 * If a proper handle is retrieved, it is locked, so make sure that you always give back the
 * semaphore after use!
 * @param url A structure with the parsed URL
 * @return If a handle is found, a pointer to the connection_handle (which is locked), if
 * 	connection is not found, NULL is returned
 */
static struct h2client_connection_handle * get_store_by_parsed_url(const struct parsed_url * url)
{
	unsigned int i;
	for(i = 0; i < (sizeof(connections) / sizeof(connections[0])); i++){
		if(xSemaphoreTake(connections[i].semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
			if(connections[i].state != CONN_EMPTY){
				if(strncmp(connections[i].server.protocol, url->protocol, url->protocol_length) == 0
					&& strncmp(connections[i].server.host, url->host, url->host_length) == 0
					&& strncmp(connections[i].server.service, url->service, url->service_length) == 0
					){
					return &(connections[i]);
				}
			}
			xSemaphoreGive(connections[i].semaphore);
		}
	}
	return NULL;
}

/**
 * Get an empty connection handle.
 * If a proper handle is retrieved, it is locked, so make sure that you always give back the
 * semaphore after use!
 * @return If an empty handle is found, a pointer to the connection_handle (which is locked), if
 * 	connection is not found, NULL is returned
 */
static struct h2client_connection_handle * get_empty_store()
{
	unsigned int i;
	for(i = 0; i < (sizeof(connections) / sizeof(connections[0])); i++){
		if(xSemaphoreTake(connections[i].semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
			if(connections[i].state == CONN_EMPTY){
				return &(connections[i]);
			}
			xSemaphoreGive(connections[i].semaphore);
		}
	}
	return NULL;
}

/**
 * Get an idle connection handle
 * This function will free the store first
 * If a proper handle is retrieved, it is locked, so make sure that you always give back the
 * semaphore after use!
 * @return If an idle handle is found, a pointer to the connection_handle (which is locked), if
 * 	connection is not found, NULL is returned
 */
static struct h2client_connection_handle * get_idle_store()
{
	unsigned int i;
	struct h2client_connection_handle * oldest = &(connections[0]);

	for(i = 1; i < (sizeof(connections) / sizeof(connections[0])); i++){
		if(connections[i].last_used < oldest->last_used){
			oldest = &(connections[i]);
		}
	}

	if(xSemaphoreTake(oldest->semaphore, ms_to_ticks(H2CLIENT_TIMEOUT_ACQ_SEMAPHORE))){
		if(oldest->current_request == NULL && uxQueueMessagesWaiting(oldest->request_queue) == 0){
			log(INFO, TAG, "Cleanup idle connection %d", oldest->conn.id);
			free_connection_handle(oldest);
			return oldest;
		}
		xSemaphoreGive(oldest->semaphore);
	}

	return NULL;
}

/**
 * Free the content of a connection handle.
 * Note that it assumes that the handle is already locked. And it will not release the
 * lock.
 * @param handle The handle to clean up
 */
static void free_connection_handle(struct h2client_connection_handle * handle)
{
		struct h2client_request_internal * r;

		// release request wait lock of current request
		if(handle->current_request != NULL){
			handle->current_request->error = true;
			xSemaphoreGive(handle->current_request->wait_semaphore);
			log(WARNING, TAG, "Connection %d: Cancelled current request", handle->conn.id);
		}

		// If items in the queue, cleanup
		while(xQueueReceive(handle->request_queue, &r, 0)){
			r->error = true;
			xSemaphoreGive(r->wait_semaphore);
			log(WARNING, TAG, "Connection %d: Cancelled request in queue", handle->conn.id);
		}

		if(handle->h2_session != NULL){
			nghttp2_session_del(handle->h2_session);
			handle->h2_session = NULL;
		}
		if(handle->conn.ssl != NULL){
			SSL_free(handle->conn.ssl);
			handle->conn.ssl = NULL;
		}
		if(handle->conn.sockfd >= 0){
			close(handle->conn.sockfd);
			handle->conn.sockfd = -1;
		}

		free(handle->server.protocol);
		handle->server.protocol = NULL;
		free(handle->server.host);
		handle->server.host = NULL;
		free(handle->server.service);
		handle->server.service = NULL;

		log(INFO, TAG, "free done");
		handle->state = CONN_EMPTY;
}

/**
 * Helper functions
 */

/**
 * Split URL string into host as port. Does not do anything with the path
 * Note that no new memory is allocated, pointers in the URL string are used instead,
 * so make sure the string keep to exist if the res is used.
 * @param url The URL string
 * @param res Pointer where to store the result
 * @return true if parsing goes well, otherwise false
 */
bool parse_url(const char * url, struct parsed_url * output)
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
		// the URL contains more than only the server address
		output->path = &(url[offset]);
		output->path_length = len - offset;
	}else{
		// the URL only contains the server address
		output->path = default_path;
		output->path_length = sizeof(default_path) - 1;
	}
	return true;
}

