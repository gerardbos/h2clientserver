#include "h2server.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>

#include <string.h>

#include "h2log.h"

#define H2SERVER_TASK_STACKSIZE		CONFIG_H2SERVER_TASK_STACKSIZE 	// Stack size in words for the task (>16KB required for mbedtls)
#define H2SERVER_TASK_PRIORITY		5

#define H2SERVER_TIMEOUT_ACQ_SEMAPHORE	500		// Timeout to wait for acquiring a lock to the server/connection bookkeeping
#define H2SERVER_LISTEN_BACKLOG		2
#define H2SERVER_CONNECTIONS_MAX	CONFIG_H2SERVER_CONNECTIONS_MAX

// Convert ms to ticks (round down)
#define ms_to_ticks(d_ms)		(TickType_t)(d_ms / portTICK_PERIOD_MS)

enum h2server_state{
	H2SERVER_EMPTY,
	H2SERVER_RUN,
	H2SERVER_STOP
};

enum connection_state{
	CONN_EMPTY,
	CONN_ACTIVE,
	CONN_CLOSING
};

struct h2server_server{
	unsigned int port;
	int sockfd;
	enum h2server_state state;
	struct h2server_endpoint endpoints[10]; // endpoint storage
	SemaphoreHandle_t semaphore;
};

struct h2server_connection{
	struct h2_connection conn;

	enum connection_state state;
	SemaphoreHandle_t semaphore;

	struct h2server_server * server;
	nghttp2_session * h2_session;
	struct h2server_stream_data * streams; // linked list of streams

	char * client_address;
	unsigned int port;
};

struct h2server_stream_data{
	struct h2server_stream_data * prev, * next;
	char * request_path;
	enum h2_method request_method;
	int h2_stream_id;
	struct h2server_endpoint * endpoint;
	enum h2_http_status status;
	void * private_data; // pointer that can be used by the callback
};

// generic functions, divided over h2client and h2server (but not made externally available)
extern ssize_t h2_nghttp2_callback_recv(nghttp2_session * session, uint8_t * buf, size_t length, int flags, void * user_data);
extern ssize_t h2_nghttp2_callback_send(nghttp2_session * session, const uint8_t * data, size_t length, int flags, void * user_data);

// nghttp2 callbacks
static int callback_on_frame_recv(nghttp2_session * session, const nghttp2_frame * frame, void * user_data);
static int callback_on_data_chunk_recv(nghttp2_session * session, uint8_t flags, int32_t stream_id, const uint8_t * data, size_t len, void * user_data);
//static int callback_on_frame_send(nghttp2_session * session, const nghttp2_frame * frame, void * user_data);
static int callback_on_stream_close(nghttp2_session * session, int32_t stream_id, uint32_t error_code, void * user_data);
static int callback_on_begin_headers(nghttp2_session * session, const nghttp2_frame * frame, void * user_data);
static int callback_on_header(nghttp2_session * session, const nghttp2_frame * frame, const uint8_t * name, size_t namelen, const uint8_t * value, size_t valuelen, uint8_t flags, void * user_data);

static ssize_t response_callback_wrapper(nghttp2_session * session, int32_t stream_id, uint8_t * buf, size_t length, uint32_t * data_flags, nghttp2_data_source * source, void * user_data);

// Operations on the stream linked lists
static void connection_add_to_streams(struct h2server_connection * connection, struct h2server_stream_data * item);
static void connection_remove_from_streams(struct h2server_connection * connection, struct h2server_stream_data * item);

// Server endpoint management
static struct h2server_endpoint * search_endpoint(struct h2server_server * server, const char * path, enum h2_method method, enum h2_http_status * status);

// task thread and helpers
static void handler_task(void * args); // task function
static void check_and_accept_new_connections(struct h2server_server * handle);
static void server_cleanup(struct h2server_server * handle);
static bool connection_setup(struct h2server_connection * connection, struct h2server_server * server, int new_sockfd);
static void h2server_handle_connection(struct h2server_connection * connection);
static void connection_close(struct h2server_connection * connection);
static void connection_close_and_cleanup(struct h2server_connection * connection);

// Local const variables
static const char * TAG = "h2server";

// Local variables
static TaskHandle_t task_handle;
static volatile unsigned int new_connection_id = 0; // TODO: Add semaphore for this item (although it is only debugging, for now)
// This context handle can be used for multiple connection.
static SSL_CTX * ssl_ctx = NULL;
// The callbacks structure can be used to setup multiple session, it can also be created
// every time a session is created, but this pollutes the heap more (with the downside that this
// takes memory continuously)
static nghttp2_session_callbacks * nghttp2_callbacks = NULL;
// servers
static struct h2server_server server;
// active connection storage
static struct h2server_connection connections[H2SERVER_CONNECTIONS_MAX];

/**
 * Initialize the basics for all servers that are running on this system.
 * Note that only one certificate set can be used for all servers, as the certificate has to be connected to the SSL
 * context. If we connect it to the SSL object, it is much slower (too slow).
 * @param certificate A PEM encoded certificate string
 * @param certificate_len The length of the certificate string
 * @param private_key A PEM encoded private key string
 * @param private_key_len The length of the private key
 * @return H2_ERROR_OK if everything is OK.
 */
int h2server_initialize(const char * certificate, size_t certificate_len, const char * private_key, size_t private_key_len)
{
	int i;

	// initialize empty servers and endpoints
	memset(&server, 0, sizeof(server));

	server.semaphore = xSemaphoreCreateBinary();
	if(server.semaphore == NULL){
		log(ERROR, TAG, "Cannot initialize server semaphore");
		goto error_server_semaphore;
	}
	xSemaphoreGive(server.semaphore);

	for(i = 0; i < sizeof(connections) / sizeof(connections[0]); i++){
		connections[i].semaphore = xSemaphoreCreateBinary();
		if(connections[i].semaphore == NULL){
			log(ERROR, TAG, "Cannot initialize connection semaphore");
			goto error_conn_semaphore;
		}
		xSemaphoreGive(connections[i].semaphore);
	}

	// initialize SSL context used for all connection
	ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());
	if(ssl_ctx == NULL){
		log(ERROR, TAG, "Cannot initialize SSL context");
		goto error_ssl_ctx;
	}

	// set supported protocols using ALPN
	SSL_CTX_set_alpn_protos(ssl_ctx, (unsigned char *)NGHTTP2_PROTO_ALPN, NGHTTP2_PROTO_ALPN_LEN);

	// Set certificate
	if(SSL_CTX_use_certificate_ASN1(ssl_ctx, certificate_len, (const unsigned char *)(certificate)) != 1){
		log(ERROR, TAG, "Error setting certificate");
		goto error_ssl;
	}

	// Set private key
	if(SSL_CTX_use_PrivateKey_ASN1(0, ssl_ctx, (const unsigned char *)(private_key), private_key_len) != 1){
		log(ERROR, TAG, "Error setting private key");
		goto error_ssl;
	}

	// nghttp2 callbacks
	nghttp2_session_callbacks_new(&nghttp2_callbacks);
	nghttp2_session_callbacks_set_send_callback(nghttp2_callbacks, h2_nghttp2_callback_send);
	nghttp2_session_callbacks_set_recv_callback(nghttp2_callbacks, h2_nghttp2_callback_recv);
	//nghttp2_session_callbacks_set_on_frame_send_callback(nghttp2_callbacks, callback_on_frame_send);
	nghttp2_session_callbacks_set_on_frame_recv_callback(nghttp2_callbacks, callback_on_frame_recv);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(nghttp2_callbacks, callback_on_data_chunk_recv);
	nghttp2_session_callbacks_set_on_stream_close_callback(nghttp2_callbacks, callback_on_stream_close);
	nghttp2_session_callbacks_set_on_header_callback(nghttp2_callbacks, callback_on_header);
	nghttp2_session_callbacks_set_on_begin_headers_callback(nghttp2_callbacks, callback_on_begin_headers);

	// create nghttp2 handler task
	if(xTaskCreate(handler_task, "h2server_handlertask", H2SERVER_TASK_STACKSIZE, NULL, H2SERVER_TASK_PRIORITY, &task_handle) != pdPASS){
		goto error_task;
	}

	log(INFO, TAG, "SSL server handler task initialized");

	return H2_ERROR_OK;

error_task:
	nghttp2_session_callbacks_del(nghttp2_callbacks);
error_ssl:
	SSL_CTX_free(ssl_ctx);
error_ssl_ctx:
error_conn_semaphore:
	while(i > 0){
		i--;
		vSemaphoreDelete(connections[i].semaphore);
	}
	vSemaphoreDelete(server.semaphore);
error_server_semaphore:
	return H2_ERROR_NO_MEM;
}

/**
 * Start a h2 server on port port
 * @param port The port where to listen to
 */
struct h2server_handle * h2server_start(unsigned int port)
{
	struct h2server_server * handle = &server;
	struct sockaddr_in addr;
	int flags;

	log(INFO, TAG, "starting h2 server on port %u", port);

	if(!xSemaphoreTake(handle->semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
		log(ERROR, TAG, "Unable to acquire server semaphore in server start");
		goto error_get_semaphore;
	}

	if(handle->state != H2SERVER_EMPTY){
		log(ERROR, TAG, "No storage for server available");
		goto error_get_server_store;
	}

	handle->port = port;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(handle->port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	handle->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(handle->sockfd < 0) {
		log(ERROR, TAG, "Unable to create socket");
		goto error_sock;
	}

	if(bind(handle->sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		log(ERROR, TAG, "Unable to bind");
		goto error_bind;
	}

	if(listen(handle->sockfd, H2SERVER_LISTEN_BACKLOG) < 0) {
		log(ERROR, TAG, "Unable to listen");
		goto error_listen;
	}

	// set the socket to non blocking, so we can use the accept() call in
	// a non blocking way.
	flags = fcntl(handle->sockfd, F_GETFL, 0);
	fcntl(handle->sockfd, F_SETFL, flags | O_NONBLOCK);

	handle->state = H2SERVER_RUN;

	xSemaphoreGive(handle->semaphore);

	return (struct h2server_handle *)handle;

error_listen:
error_bind:
	close(handle->sockfd);
error_sock:
error_get_server_store:
	xSemaphoreGive(handle->semaphore);
error_get_semaphore:
	return NULL;
}

/**
 * Stop the server
 * Note that this function only triggers a stop action. The real closing of the
 * server is done in a separate thread.
 * @param handle A pointer to the server handle
 */
bool h2server_stop(struct h2server_handle * handle_)
{
	struct h2server_server * handle = (struct h2server_server *)handle_;
	if(xSemaphoreTake(handle->semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
		handle->state = H2SERVER_STOP;
		xSemaphoreGive(handle->semaphore);
		return true;
	}else{
		log(ERROR, TAG, "Error acquiring semaphore for server handle to stop the server");
		return false;
	}
}

/**
 * Register a new endpoint for server handle_
 * This function copies all the data from endpoint, so the caller can discard the data later.
 * @param handle_ A handle to the server
 * @param endpoint The endpoint to register.
 * @return true if the registration is OK.
 */
bool h2server_register_endpoint(struct h2server_handle * handle_, struct h2server_endpoint * endpoint)
{
	int i;
	bool found = false;
	struct h2server_server * handle = (struct h2server_server *)handle_;

	if(xSemaphoreTake(handle->semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
		// find empty one
		for(i = 0; i < (sizeof(handle->endpoints) / sizeof(handle->endpoints[0])) && !found; i++){
			if(handle->endpoints[i].path == NULL){
				bool error = false;

				const char * path = malloc(strlen(endpoint->path) + 1);
				if(path == NULL)
					error = true;

				strcpy((char *)path, endpoint->path);

				struct h2server_endpoint_header * read = endpoint->headers;
				struct h2server_endpoint_header * write = NULL;
				while(!error && read != NULL){
					// malloc all memory required for the header at once
					char * tmp = malloc(sizeof(struct h2server_endpoint_header)
							+ strlen(read->name) + 1
							+ strlen(read->value) + 1);

					if(tmp != NULL){
						write = (struct h2server_endpoint_header *)tmp;
						write->name = tmp + sizeof(struct h2server_endpoint_header);
						write->value = tmp + sizeof(struct h2server_endpoint_header) + strlen(read->name) + 1;

						// fill data
						strcpy((char *)write->name, read->name);
						strcpy((char *)write->value, read->value);

						log(INFO, TAG, "add header: %s: %s", write->name, write->value);
						h2server_endpoint_add_header(&handle->endpoints[i], write);
						read = read->next;
					}else{
						error = true;
					}
				}

				if(error){
					read = handle->endpoints[i].headers;
					while(read != NULL){
						struct h2server_endpoint_header * tmp = read->next;
						free(read);
						read = tmp;
					}
					if(path != NULL)
						free((char *)path);
				}else{
					handle->endpoints[i].path = path;
					handle->endpoints[i].method = endpoint->method;
					handle->endpoints[i].headers = write; // as we are adding to the head of the list, we can use write ptr here
					handle->endpoints[i].headers_count = endpoint->headers_count;
					handle->endpoints[i].callback_request = endpoint->callback_request;
					handle->endpoints[i].callback_response = endpoint->callback_response;
					found = true;
				}
			}
		}
		xSemaphoreGive(handle->semaphore);
	}else{
		log(ERROR, TAG, "Error acquiring semaphore");
	}

	return found;
}

/**
 * task thread and helpers
 */

/**
 * Handle all servers and active connections
 */
static void handler_task(void * args)
{
	while(true){
		struct h2server_server * handle = &server;
		int i;

		if(xSemaphoreTake(handle->semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
			//log(INFO, TAG, "semaphore taken in task");
			switch(handle->state){
				case H2SERVER_EMPTY:
					// do nothing
					break;
				case H2SERVER_RUN:
					check_and_accept_new_connections(handle);
					break;
				case H2SERVER_STOP:
					server_cleanup(handle);
					break;
				default:
					log(ERROR, TAG, "Unknown state %d", handle->state);
			}
			xSemaphoreGive(handle->semaphore);
			//log(INFO, TAG, "give semaphore in task");
		}else{
			log(INFO, TAG, "Unable to acquire server semaphore in task");
		}

		// handle all connections
		for(i = 0; i < sizeof(connections) / sizeof(connections[0]); i++){
			if(xSemaphoreTake(connections[i].semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
				switch(connections[i].state){
					case CONN_EMPTY:
						// do nothing
						break;
					case CONN_ACTIVE:
						h2server_handle_connection(&connections[i]);
						break;
					case CONN_CLOSING:
						connection_close_and_cleanup(&connections[i]);
						break;

				}
				xSemaphoreGive(connections[i].semaphore);
			}else{
				log(INFO, TAG, "Unable to acquire connection[%d] semaphore in task", i);
			}
		}

		vTaskDelay(2);
	}
}

/**
 * Check if new connections are waiting. If so, and there is still room for
 * new connections, make the connection.
 * Note that the caller of this function is required to have the mutex to the
 * handle.
 * @param handle Handle to the server object.
 */
static void check_and_accept_new_connections(struct h2server_server * handle)
{
	bool done = false;
	while(!done){
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);
		int sockfd = accept(handle->sockfd, (struct sockaddr*)&addr, &len);
		if(sockfd < 0){
			// error detected, check for EAGAIN or EWOULDBLOCK
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				// no waiting connections
				done = true;
			}else{
				log(ERROR, TAG, "Error connecting: %d, errno: %d", sockfd, errno);
			}
		}else{
			// setup connection
			int i;
			bool found = false;

			for(i = 0; i < sizeof(connections) / sizeof(connections[0]) && !found; i++){
				if(xSemaphoreTake(connections[i].semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
					if(connections[i].state == CONN_EMPTY){
						found = true;
						if(!connection_setup(&connections[i], handle, sockfd))
							log(ERROR, TAG, "Unable to setup connection");
					}
					xSemaphoreGive(connections[i].semaphore);
				}else{
					log(WARNING, TAG, "Error acquiring connection semaphore for getting storage memory");
				}
			}

			if(!found){
				log(ERROR, TAG, "Error allocating connection storage memory");
				// no store available anymore, so just stop adding new items
				done = true;
			}
		}
	}
}

/**
 * Cleanup server. This closes listening socket, closes all connections and
 * removes all endpoints.
 * Note that the caller of this function is required to have the mutex to the
 * handle.
 * @param handle A handle to the server structure
 */
static void server_cleanup(struct h2server_server * handle)
{
	int i;

	close(handle->sockfd);

	for(i = 0; i < sizeof(connections) / sizeof(connections[0]); i++){
		if(connections[i].server == handle) // check if this connection is from this server
			connection_close(&connections[i]);
	}

	for(i = 0; i < sizeof(handle->endpoints) / sizeof(handle->endpoints[0]); i++){
		free((char *)handle->endpoints[i].path);

		struct h2server_endpoint_header * read = handle->endpoints[i].headers;
		while(read != NULL){
			struct h2server_endpoint_header * tmp = read->next;
			free(read);
			read = tmp;
		}

		handle->endpoints[i].method = H2_METHOD_UNKNOWN;
		handle->endpoints[i].callback_request = NULL;
		handle->endpoints[i].callback_response = NULL;
		handle->endpoints[i].path = NULL;
	}

	log(INFO, TAG, "h2 server on port %u stopped", handle->port);
	handle->port = 0;
	handle->state = H2SERVER_EMPTY;
}

/**
 * Setup a new connection. This function also handles the SSL setup.
 * Note that the caller of this function is required to have the mutex to the
 * connection.
 * @param connection Handle to the connection
 * @param server Handle to the server the connection is originating from
 * @param new_sockfd The new socket for this connection
 * @return true if the connection setup was OK
 */
static bool connection_setup(struct h2server_connection * connection, struct h2server_server * server, int new_sockfd)
{
	int r;

	connection->conn.id = new_connection_id++;
	log(INFO, TAG, "New connection: %u", connection->conn.id);

	connection->conn.ssl = SSL_new(ssl_ctx);
	if(connection->conn.ssl == NULL){
		log(ERROR, TAG, "Connection %u: Error in SSL_new", connection->conn.id);
		goto error_sslnew;
	}

	connection->conn.sockfd = new_sockfd;
	connection->server = server;

	int flags = fcntl(connection->conn.sockfd, F_GETFL, 0);
	fcntl(connection->conn.sockfd, F_SETFL, flags | O_NONBLOCK);

	// set TCP_NODELAY
	int val = 1;
	if(setsockopt(connection->conn.sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val)) != 0){
		log(WARNING, TAG, "Connection %u: Unable to set TCP_NODELAY on socket", connection->conn.id);
	}

	// TODO: get info from socket using getnameinfo();
	if(!SSL_set_fd(connection->conn.ssl, connection->conn.sockfd)){
		log(ERROR, TAG, "Error setting fd");
		goto error_sslsetfd;
	}

	r = SSL_accept(connection->conn.ssl);
	if(r <= 0){
		int error = SSL_get_error(connection->conn.ssl, r);
		log(ERROR, TAG, "Connection %u: Failed accepting SSL (return: %d, error: %d)", connection->conn.id, r, error);
		goto error_sslaccept;
	}

	if(nghttp2_session_server_new(&connection->h2_session, nghttp2_callbacks, connection) != 0){
		log(ERROR, TAG, "Connection %u: Error setting up nghttp2 server session.", connection->conn.id);
		goto error_h2session;
	}

	// send server connection header
	nghttp2_settings_entry iv[] = {
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 10}
	};

	r = nghttp2_submit_settings(connection->h2_session, NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(iv[0]));
	if(r != 0){
		log(WARNING, TAG, "Connection: %u: Error submitting session", connection->conn.id);
	}

	connection->state = CONN_ACTIVE;
	return true;

error_h2session:
error_sslaccept:
error_sslsetfd:
	SSL_free(connection->conn.ssl);
error_sslnew:

	return false;
}

/**
 * Close a connection. Note that the real closing is done inside the task
 * Note that the caller of this function is required to have the mutex to the
 * connection.
 * @param connection Pointer to the connection
 */
static void connection_close(struct h2server_connection * connection)
{
	// only close active connections ;)
	if(connection->state == CONN_ACTIVE)
		connection->state = CONN_CLOSING;
}

/**
 * Close and cleanup a connection.
 * Note that the caller of this function is required to have the mutex to the
 * connection.
 * @param connection Pointer to the connection
 */
static void connection_close_and_cleanup(struct h2server_connection * connection)
{
	log(INFO, TAG, "Connection %u: Cleanup", connection->conn.id);
	int r;
	struct h2server_stream_data * s = connection->streams;

	// free linked list with streams
	while(s != NULL){
		struct h2server_stream_data * next = s->next;

		connection_remove_from_streams(connection, s);
		free(s);
		s = next;
	}
	nghttp2_session_del(connection->h2_session);
	connection->h2_session = NULL;


	SSL_shutdown(connection->conn.ssl);
	r = SSL_shutdown(connection->conn.ssl);
	if(r == 0)
		log(INFO, TAG, "Connection %u: Shutdown of SSL not finished", connection->conn.id);
	if(r < 0)
		log(WARNING, TAG, "Connection %u: Error shutting down SSL, still closing", connection->conn.id);

	close(connection->conn.sockfd);
	connection->conn.sockfd = -1;

	if(connection->conn.ssl != NULL){
		SSL_free(connection->conn.ssl);
		connection->conn.ssl = NULL;
	}

	connection->state = CONN_EMPTY;
}

/**
 * Handle the connection.
 * This function manages reads and writes to this connection and verifies that the
 * other end wants to keep the connection open. If not, it will initiate a connection close.
 * Note that the caller of this function is required to have the mutex to the
 * connection.
 * @param connection Pointer to the connection
 */
static void h2server_handle_connection(struct h2server_connection * connection)
{
	int r;

	//log(INFO, TAG, "send");
	if((r = nghttp2_session_send(connection->h2_session)) != 0){
		log(ERROR, TAG, "Connection %d: Send failed (error %d)", connection->conn.id, r);
	}

	//log(INFO, TAG, "recv");
	if((r = nghttp2_session_recv(connection->h2_session)) != 0){
		if(r == NGHTTP2_ERR_EOF){
			// other end closed the connection. So we should do that also
			log(INFO, TAG, "Connection %d: EOF received, closing connection", connection->conn.id);
			connection_close(connection);
			return;
		}
		log(ERROR, TAG, "Connection %d: Receive failed (error %d)", connection->conn.id, r);
	}

	if(nghttp2_session_want_read(connection->h2_session) == 0 && nghttp2_session_want_write(connection->h2_session) == 0){
		log(INFO, TAG, "Connection %d: want_read == 0 && want_write == 0, closing connection", connection->conn.id);
		connection_close(connection);
		return;
	}
}

/**
 * nghttp2 callbacks
 */

/**
 * Callback when a frame is received
 * Used to trigger read and write of the get/post/put data
 * @param user_data This shall be a pointer to the h2server_connection structure.
 */
static int callback_on_frame_recv(nghttp2_session * session, const nghttp2_frame * frame, void * user_data)
{
	struct h2server_connection * connection = (struct h2server_connection *)user_data;
	struct h2server_stream_data * s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

	// For DATA and HEADERS frame, this callback may be called after
	// on_stream_close_callback. Check that stream still alive.
	if(s == NULL)
		return 0;

	if(frame->hd.type == NGHTTP2_HEADERS){
		if(xSemaphoreTake(connection->server->semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
			s->endpoint = search_endpoint(connection->server, s->request_path, s->request_method, &s->status);
			log(INFO, TAG, "Connection: %u: %s %s %u", connection->conn.id, h2_method_to_string(s->request_method), s->request_path, s->status);
			xSemaphoreGive(connection->server->semaphore);
		}else{
			log(ERROR, TAG, "Connection %u: Error obtaining server semaphore in %s to set endpoint", connection->conn.id, __func__);
		}
	}

	if((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA)
			&& frame->hd.flags & NGHTTP2_FLAG_END_STREAM){
		int err;
		if(s->endpoint == NULL){
			const char * status_string = h2_http_status_to_string(s->status);
			// endpoint not found, send a 404 (Not found) or 405 (Method not allowed)
			nghttp2_nv hdrs[] = {h2_make_nv(h2_header_status, sizeof(h2_header_status) - 1, status_string, strlen(status_string))};

			err = nghttp2_submit_response(session, frame->hd.stream_id, hdrs, sizeof(hdrs) / sizeof(hdrs[0]), NULL);
		}else{
			if(xSemaphoreTake(connection->server->semaphore, ms_to_ticks(H2SERVER_TIMEOUT_ACQ_SEMAPHORE))){
				// endpoint found
				const char * status_string = h2_http_status_to_string(s->status);
				// create storage for headers, the status headers is always added, the rest depends on the endpoint
				nghttp2_nv hdrs[1 + s->endpoint->headers_count];
				unsigned char hdrs_cnt = 0;
				struct h2server_endpoint_header * header = s->endpoint->headers;

				// set headers
				h2_assign_nv(&hdrs[hdrs_cnt++], h2_header_status, sizeof(h2_header_status) - 1, status_string, strlen(status_string));
				while(header != NULL){
					h2_assign_nv(&hdrs[hdrs_cnt++], header->name, strlen(header->name), header->value, strlen(header->value));
					header = header->next;
				}

				nghttp2_data_provider p = {.read_callback = response_callback_wrapper, .source = {.ptr = s->endpoint}};

				err = nghttp2_submit_response(session, s->h2_stream_id, hdrs, hdrs_cnt, &p);

				xSemaphoreGive(connection->server->semaphore);
			}else{
				err = 1;
				log(ERROR, TAG, "Connection %u: Error obtaining server semaphore in %s process request", connection->conn.id, __func__);
			}
		}

		if(err != 0)
			log(ERROR, TAG, "Connection %u: Error submitting response (%d)", connection->conn.id, err);
	}

	return 0;
}

/**
 * Callback when a new data chunk is received
 * Used to read data chunks that contain the post/put request data.
 * @param user_data This shall be a pointer to the h2server_connection structure.
 */
static int callback_on_data_chunk_recv(nghttp2_session * session, uint8_t flags, int32_t stream_id, const uint8_t * data, size_t len, void * user_data)
{
	struct h2server_connection * connection = (struct h2server_connection *)user_data;
	struct h2server_stream_data * s = nghttp2_session_get_stream_user_data(session, stream_id);

	// stream closed in the mean time
	if(s == NULL)
		return 0;

	if(s->endpoint == NULL)
		return 0;

	if(s->endpoint->callback_request != NULL){
		s->endpoint->callback_request((char *)data, len, flags & NGHTTP2_FLAG_END_STREAM, &(s->private_data));
	}else{
		log(INFO, TAG, "Connection %u: No request data callback set", connection->conn.id);
	}

	return 0;
}

/**
 * Callback when a frame is send
 * only DEBUG, enable when needed
 * @param user_data This shall be a pointer to the h2server_connection structure.
 */
/*static int callback_on_frame_send(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
	//struct h2server_connection * connection = (struct h2server_connection *)user_data;

	switch(frame->hd.type){
		case NGHTTP2_HEADERS:
			log(INFO, TAG, "send headers");
			break;
		case NGHTTP2_DATA:
			log(INFO, TAG, "send data");
			break;
		case NGHTTP2_SETTINGS:
			log(INFO, TAG, "send settings");
			break;
		default:
			log(INFO, TAG, "send frame: %d", frame->hd.type);
			break;
	}
	return 0;
}*/

/**
 * Callback when a stream close is requested.
 * This function frees the stream and removes it from the connection.
 * @param user_data This shall be a pointer to the h2server_connection structure.
 */
static int callback_on_stream_close(nghttp2_session * session, int32_t stream_id, uint32_t error_code, void * user_data)
{
	struct h2server_connection * connection = (struct h2server_connection *)user_data;
	struct h2server_stream_data * s = nghttp2_session_get_stream_user_data(session, stream_id);
	if(s == NULL) // stream already closed
		return 0;

	connection_remove_from_streams(connection, s);
	free(s);
	return 0;
}

/**
 * Callback on begin of headers
 * This function is used to create the steam bookkeeping, as this is the point where a stream starts
 * @param user_data This shall be a pointer to the h2server_connection structure.
 */
static int callback_on_begin_headers(nghttp2_session * session, const nghttp2_frame * frame, void * user_data)
{
	struct h2server_connection * connection = (struct h2server_connection *)user_data;

	switch(frame->hd.type){
		case NGHTTP2_HEADERS:
		case NGHTTP2_HCAT_REQUEST:
			{
				struct h2server_stream_data * s = malloc(sizeof(struct h2server_stream_data));
				memset(s, 0, sizeof(struct h2server_stream_data));
				s->h2_stream_id = frame->hd.stream_id;
				nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, s);
				// add stream data to connection linked list
				connection_add_to_streams(connection, s);
			}
			break;
		default:
			break;
	}
	return 0;
}

/**
 * Callback on header
 * Used to process every header that is inside the request
 * @param user_data This shall be a pointer to the h2server_connection structure.
 */
static int callback_on_header(nghttp2_session * session, const nghttp2_frame * frame, const uint8_t * name, size_t namelen, const uint8_t * value, size_t valuelen, uint8_t flags, void * user_data)
{
	struct h2server_stream_data * s;
	switch(frame->hd.type){
		case NGHTTP2_HEADERS:
			{
				bool found = false;

				if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
					break;

				s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
				if(!s)
					break;

				// check if PATH header
				if(namelen == h2_const_strlen(h2_header_path) && memcmp(h2_header_path, name, h2_const_strlen(h2_header_path)) == 0){
					s->request_path = malloc(valuelen + 1);
					memcpy(s->request_path, value, valuelen);
					s->request_path[valuelen] = '\0';
					log(DEBUG, TAG, "Header path: %s", s->request_path);
					found = true;
				}
				// check if METHOD header
				if(namelen == h2_const_strlen(h2_header_method) && memcmp(h2_header_method, name, h2_const_strlen(h2_header_method)) == 0){
					s->request_method = h2_method_from_string((const char *)value, valuelen);
					log(DEBUG, TAG, "Header method: %d [%s]", s->request_method, h2_method_to_string(s->request_method));
					found = true;
				}

				if(!found)
					log(DEBUG, TAG, "Header unknown: %.*s: %.*s", namelen, name, valuelen, value);
			}
			break;
		default:
			break;
	}

	return 0;
}

/**
 * Wrapper for the response data callback. This is not a direct nghttp2 callback, but it'll
 * hide all the http2 parameters for the endpoint handler
 */
static ssize_t response_callback_wrapper(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	int r = 0;
	bool finished = false;
	struct h2server_stream_data * s = nghttp2_session_get_stream_user_data(session, stream_id);

	if(s != NULL){
		struct h2server_endpoint * endpoint = source->ptr;

		if(endpoint->callback_response != NULL){
			r = endpoint->callback_response((char *)buf, length, &finished, &(s->private_data));
		}else{
			finished = true;
		}

	}else{
		finished = true;
	}

	if(finished)
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;

	return r;
}

/**
 * Operations on the stream linked lists
 */

/**
 * Add item to the double linked list of the connection
 * @param connection The connection where to add the stream
 * @param item The item to add
 * @return true if no error occurred
 */
static void connection_add_to_streams(struct h2server_connection * connection, struct h2server_stream_data * item)
{
	item->prev = NULL; // Not required, as it should be NULL already
	item->next = connection->streams;
	connection->streams = item;
}

/**
 * Remove item from double linked list of the connection
 * @param connection The connection where to remove the stream
 * @param item Item to remove
 * @return true if no error occurred
 */
static void connection_remove_from_streams(struct h2server_connection * connection, struct h2server_stream_data * item)
{
	struct h2server_stream_data * prev = item->prev;
	struct h2server_stream_data * next = item->next;

	if(prev != NULL)
		prev->next = next;

	if(next != NULL)
		next->prev = prev;

	if(item == connection->streams) // head of the list
		connection->streams = next;
}

/**
 * Server endpoint management
 */

/**
 * Search an endpoint based on path and method
 * @param server Server handle
 * @param path The endpoint path
 * @param method The endpoint method
 * @param status The HTTP status will be returned in this variable. (e.g. 404 if not found, 200 if found, etc.). This is also
 * 	filled in when no endpoint is found (NULL is returned)
 * @return A pointer to the structure if found, if not found, NULL is returned.
 */
static struct h2server_endpoint * search_endpoint(struct h2server_server * server, const char * path, enum h2_method method, enum h2_http_status * status)
{
	int i;
	struct h2server_endpoint * endpoint = NULL;

	// set status to 404 initially
	*status = H2_NOT_FOUND;

	for(i = 0; i < (sizeof(server->endpoints) / sizeof(server->endpoints[0])); i++){
		if(server->endpoints[i].path != NULL){ // skip unused endpoints
			if(strlen(path) == strlen(server->endpoints[i].path) && memcmp(path, server->endpoints[i].path, strlen(server->endpoints[i].path)) == 0){
				// found matching path
				// now check method
				if(method == server->endpoints[i].method){
					endpoint = &(server->endpoints[i]);
					*status = H2_OK;
					break;
				}else{
					*status = H2_METHOD_NOT_ALLOWED;
				}
			}
		}
	}

	return endpoint;
}

