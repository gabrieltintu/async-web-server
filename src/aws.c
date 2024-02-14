// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <errno.h>

#include "aws.h"
#include "utils/util.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *)p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	/* Prepare the connection buffer to send the reply header. */

	const char *header_format = "HTTP/1.1 200 OK\r\n"
								"Content-Length: %ld\r\n"
								"Connection: close\r\n"
								"\r\n";

	size_t header_len = snprintf(NULL, 0, header_format, conn->file_size);

	if (BUFSIZ - conn->send_len >= header_len) {
		snprintf(conn->send_buffer + conn->send_len, BUFSIZ - conn->send_len, header_format, conn->file_size);
		conn->send_len += header_len;
		conn->state = STATE_SENDING_HEADER;
	} else {
		perror("header");
		conn->state = STATE_CONNECTION_CLOSED;
	}
}

static void connection_prepare_send_404(struct connection *conn)
{
	/* Prepare the connection buffer to send the 404 header. */

	const char *not_found_format = "HTTP/1.1 404 Not Found\r\n"
								   "Content-Length: 0\r\n"
								   "Connection: close\r\n"
								   "\r\n";

	size_t not_found_len = strlen(not_found_format);

	if (BUFSIZ - conn->send_len >= not_found_len) {
		snprintf(conn->send_buffer + conn->send_len, BUFSIZ - conn->send_len, "%s", not_found_format);
		conn->send_len += not_found_len;
		conn->state = STATE_SENDING_404;
	} else {
		perror("404");
		conn->state = STATE_CONNECTION_CLOSED;
	}
}

static enum resource_type connection_get_resource_type(struct connection *conn)
{
	/* Get resource type depending on request path/filename. Filename should
	 * point to the static or dynamic folder.
	 */

	if (strstr(conn->request_path, "static") != NULL) {
		conn->res_type = RESOURCE_TYPE_STATIC;
		return RESOURCE_TYPE_STATIC;
	}

	if (strstr(conn->request_path, "dynamic") != NULL) {
		conn->res_type = RESOURCE_TYPE_DYNAMIC;
		return RESOURCE_TYPE_DYNAMIC;
	}

	conn->res_type = RESOURCE_TYPE_NONE;
	return RESOURCE_TYPE_NONE;
}


struct connection *connection_create(int sockfd)
{
	/* Initialize connection structure on given socket. */

	struct connection *conn = malloc(sizeof(*conn));

	DIE(conn == NULL, "malloc");

	conn->sockfd = sockfd;
	memset(conn->recv_buffer, 0, BUFSIZ);
	memset(conn->send_buffer, 0, BUFSIZ);
	memset(conn->filename, 0, BUFSIZ);
	memset(conn->request_path, 0, BUFSIZ);
	conn->recv_len = 0;
	conn->send_len = 0;

	return conn;
}

void connection_start_async_io(struct connection *conn)
{
	/* Start asynchronous operation (read from file).
	 * Use io_submit(2) & friends for reading data asynchronously.
	 */

	conn->ctx = 0;
	int rc = io_setup(1, &conn->ctx);

	DIE(rc < 0, "io_setup");

	conn->iocb.data = (void *)(uintptr_t)conn;
	conn->piocb[0] = &conn->iocb;

	if (io_submit(conn->ctx, 1, conn->piocb) < 0) {
		perror("io_submit");
		conn->state = STATE_CONNECTION_CLOSED;
	} else {
		conn->state = STATE_ASYNC_ONGOING;
	}
}

void connection_remove(struct connection *conn)
{
	/* Remove connection handler. */

	close(conn->sockfd);
	conn->state = STATE_CONNECTION_CLOSED;
	free(conn);
}

static void set_socket_nonblocking(int sockfd)
{
	int flags = fcntl(sockfd, F_GETFL, 0);

	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void handle_new_connection(void)
{
	int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct connection *conn;
	int rc;

	/* Accept new connection. */
	sockfd = accept(listenfd, (SSA *) &addr, &addrlen);
	DIE(sockfd < 0, "accept");

	/* Set socket to be non-blocking. */
	set_socket_nonblocking(sockfd);

	/* Instantiate new connection handler. */
	conn = connection_create(sockfd);

	/* Add socket to epoll. */
	rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);

	DIE(rc < 0, "w_epoll_add_in");

	/* Initialize HTTP_REQUEST parser. */
	http_parser_init(&conn->request_parser, HTTP_REQUEST);
	conn->request_parser.data = conn;
}

void receive_data(struct connection *conn)
{
	/* Receive message on socket.
	 * Store message in recv_buffer in struct connection.
	 */

	ssize_t bytes_recv;

	conn->recv_len = 0;

	while (1) {
		bytes_recv = recv(conn->sockfd, conn->recv_buffer + conn->recv_len, BUFSIZ, 0);

		if (bytes_recv <= 0)
			break;

		conn->recv_len += bytes_recv;
	}

	conn->state = STATE_RECEIVING_DATA;
}

int connection_open_file(struct connection *conn)
{
	/* Open file and update connection fields. */

	char *new_request_path = malloc((sizeof(conn->request_path + 1) * sizeof(char)));

	new_request_path[0] = '.';
	new_request_path[1] = '\0';

	strcat(new_request_path, conn->request_path);
	conn->fd = open(new_request_path, O_RDWR);
	free(new_request_path);

	if (conn->fd < 0) {
		perror("open");
		return -1;
	}

	struct stat file_stat;

	if (fstat(conn->fd, &file_stat) == 0) {
		conn->file_size = file_stat.st_size;
		conn->file_pos = 0;
	} else {
		perror("fstat");
		close(conn->fd);
		return -1;
	}

	return 0;
}

void connection_complete_async_io(struct connection *conn)
{
	/* Complete asynchronous operation; operation returns successfully.
	 * Prepare socket for sending.
	 */

	off_t offset = 0;
	ssize_t remaining_bytes = conn->send_len;

	while (remaining_bytes > 0) {
		ssize_t bytes_sent = send(conn->sockfd, conn->send_buffer + (conn->send_len - remaining_bytes), remaining_bytes, 0);

		if (bytes_sent <= 0) {
			conn->state = STATE_CONNECTION_CLOSED;
			return;
		}

		offset += bytes_sent;
		remaining_bytes -= bytes_sent;

		if (offset == conn->send_len) {
			conn->state = STATE_CONNECTION_CLOSED;
			return;
		}
	}
}

int parse_header(struct connection *conn)
{
	/* Parse the HTTP header and extract the file path. */
	/* Use mostly null settings except for on_path callback. */

	http_parser_settings settings_on_path = {
		.on_message_begin = 0,
		.on_header_field = 0,
		.on_header_value = 0,
		.on_path = aws_on_path_cb,
		.on_url = 0,
		.on_fragment = 0,
		.on_query_string = 0,
		.on_body = 0,
		.on_headers_complete = 0,
		.on_message_complete = 0
	};

	http_parser_init(&conn->request_parser, HTTP_REQUEST);
	conn->request_parser.data = conn;
	http_parser_execute(&conn->request_parser, &settings_on_path, conn->recv_buffer, conn->recv_len);

	return 0;
}

enum connection_state connection_send_static(struct connection *conn)
{
	/* Send static data using sendfile(2). */

	off_t offset = conn->file_pos;
	ssize_t remaining_bytes = conn->file_size - conn->file_pos;

	while (remaining_bytes > 0) {
		ssize_t bytes_sent = sendfile(conn->sockfd, conn->fd, &offset, remaining_bytes);

		if (bytes_sent < 0) {
			perror("sendfile");
			close(conn->fd);
			return STATE_CONNECTION_CLOSED;
		}

		if (bytes_sent <= 0)
			break;

		conn->file_pos += bytes_sent;
		remaining_bytes -= bytes_sent;
	}

	close(conn->fd);

	if (conn->file_pos == conn->file_size) {
		conn->file_pos = 0;
		return STATE_CONNECTION_CLOSED;
	}

	return STATE_SENDING_DATA;
}

int connection_send_data(struct connection *conn)
{
	/* May be used as a helper function. */
	/* Send as much data as possible from the connection send buffer.
	 * Returns the number of bytes sent or -1 if an error occurred
	 */

	while (conn->send_pos < conn->send_len) {
		ssize_t bytes_sent = send(conn->sockfd, conn->send_buffer + conn->send_pos, conn->send_len - conn->send_pos, 0);

		if (bytes_sent < 0)
			return -1;

		conn->send_pos += bytes_sent;

		if (conn->send_pos == conn->send_len) {
			conn->send_pos = 0;
			conn->send_len = 0;
			return bytes_sent;
		}
	}

	conn->send_pos = 0;
	conn->send_len = 0;

	return 0;
}


int connection_send_dynamic(struct connection *conn)
{
	/* Read data asynchronously.
	 * Returns 0 on success and -1 on error.
	 */

	struct io_event events[1];
	ssize_t bytes_read;

	do {
		io_prep_pread(&conn->iocb, conn->fd, conn->send_buffer, BUFSIZ, conn->file_pos);

		if (io_submit(conn->ctx, 1, &conn->piocb[0]) < 0)
			return STATE_CONNECTION_CLOSED;

		int num_events = io_getevents(conn->ctx, 1, 1, events, NULL);

		if (num_events == -1) {
			return STATE_CONNECTION_CLOSED;
		} else if (num_events > 0) {
			bytes_read = events[0].res;

			if (bytes_read > 0) {
				conn->send_len = bytes_read;
				connection_complete_async_io(conn);
				conn->file_pos += bytes_read;
			}
		}
	} while (bytes_read > 0);

	if (conn->file_pos == conn->file_size) {
		conn->file_pos = 0;
		conn->send_pos = 0;
		conn->send_len = 0;
		return STATE_CONNECTION_CLOSED;
	}

	return STATE_ASYNC_ONGOING;
}

void handle_input(struct connection *conn)
{
	/* Handle input information: may be a new message or notification of
	 * completion of an asynchronous I/O operation.
	 */

	receive_data(conn);

	if (conn->state == STATE_RECEIVING_DATA) {
		if (parse_header(conn) == 0) {
			if (conn->have_path) {
				conn->filename[0] = '\0';
				strcat(conn->filename, conn->request_path);
				conn->filename[strlen(conn->filename)] = '\0';
			}

			if (connection_open_file(conn) == 0)
				connection_prepare_send_reply_header(conn);
			else
				connection_prepare_send_404(conn);
		}
	}
}

void handle_output(struct connection *conn)
{
	/* Handle output information: may be a new valid requests or notification of
	 * completion of an asynchronous I/O operation or invalid requests.
	 */

	enum resource_type type = connection_get_resource_type(conn);

	if (conn->state == STATE_SENDING_HEADER || conn->state == STATE_SENDING_404) {
		int bytes_sent = connection_send_data(conn);

		if (bytes_sent < 0) {
			conn->state = STATE_CONNECTION_CLOSED;
		} else if (bytes_sent > 0) {
			if (conn->state == STATE_SENDING_HEADER) {
				if (type == RESOURCE_TYPE_STATIC) {
					conn->state = STATE_SENDING_DATA;
				} else if (type == RESOURCE_TYPE_DYNAMIC) {
					connection_start_async_io(conn);
					conn->state = STATE_ASYNC_ONGOING;
				}
			} else {
				conn->state = STATE_CONNECTION_CLOSED;
			}
		}
	}

	if (conn->state == STATE_SENDING_DATA) {
		enum connection_state send_state = connection_send_static(conn);

		if (send_state == STATE_CONNECTION_CLOSED)
			conn->state = STATE_CONNECTION_CLOSED;
	}

	if (conn->state == STATE_ASYNC_ONGOING) {
		struct io_event events[1];
		int num_events = io_getevents(conn->ctx, 1, 1, events, NULL);

		if (num_events > 0) {
			enum connection_state send_state = connection_send_dynamic(conn);

			if (send_state == STATE_CONNECTION_CLOSED)
				conn->state = STATE_CONNECTION_CLOSED;
		}
	}

	w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	connection_remove(conn);
}

void handle_client(uint32_t event, struct connection *conn)
{
	handle_input(conn);
	handle_output(conn);
}

int main(void)
{
	int rc;

	/* Initialize multiplexing. */
	epollfd = w_epoll_create();

	DIE(epollfd < 0, "w_epoll_create");

	/* Create server socket. */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);

	DIE(listenfd < 0, "tcp_create_listener");

	/* Add server socket to epoll object */
	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	while (1) {
		struct epoll_event rev;

		/* Wait for events. */
		rc = w_epoll_wait_infinite(epollfd, &rev);

		DIE(rc < 0, "w_epoll_wait_infinite");

		/* Switch event types; consider:
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */

		if (rev.data.fd == listenfd) {
			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else {
			handle_client(rev.events, rev.data.ptr);
		}
	}

	return 0;
}
