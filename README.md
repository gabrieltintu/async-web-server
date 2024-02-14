# Asynchronous Web Server

## Objectives

- Deepening the concepts related to working with sockets.
- Developing skills in implementing and designing applications that use asynchronous operations and other advanced I/O operations.
- Deepening the use of the API for advanced I/O operations in the Linux operating system.

## Statement

Implement a web server that uses the following advanced I/O operations:

- Asynchronous operations on files
- Non-blocking operations on sockets
- Zero-copying
- Multiplexing I/O operations

The server implements a limited functionality of the HTTP protocol: passing files to clients.

The web server will use the multiplexing API to wait for connections from clients - [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html).
On the established connections, requests from clients will be received and then responses will be distributed to them.


The server will serve files from the `AWS_DOCUMENT_ROOT` directory, defined within the assignments' [header](./skel/aws.h).
Files are only found in subdirectories `AWS_DOCUMENT_ROOT/static/` and `AWS_DOCUMENT_ROOT/dynamic/`.
The corresponding request paths will be, for example, `AWS_DOCUMENT_ROOT/static/test.dat` and `AWS_DOCUMENT_ROOT/dynamic/test.dat`.
The file processing will be:

- The files in the `AWS_DOCUMENT_ROOT/static/` directory are static files that will be transmitted to clients using the zero-copying API - [sendfile](https://man7.org/linux/man-pages/man2/sendfile.2.html)]
- Files in the `AWS_DOCUMENT_ROOT/dynamic/` directory are files that are supposed to require a server-side post-processing phase. These files will be read from disk using the asynchronous API and then pushed to the clients. Streaming will use non-blocking sockets (Linux)
- An [HTTP 404](https://en.wikipedia.org/wiki/HTTP_404) message will be sent for invalid request paths

After transmitting a file, according to the HTTP protocol, the connection is closed.

### Details and recommendations for the implementation

- Implementing the assignment requires having a state machine for each connection, which you periodically query and update as the transfer proceeds.
Check the `connection_state` data structure defined in the [assignment header](./skel/awh.h).
- Find the `connection` data structure defined in the [assignment header](./skel/awh.h).
This can be used to keep track of an open connection.
- Definitions of other useful macros and data structures can be found in the assignment header.
- HTTP responses will have the code `200` for existing files and `404` for not existing files.
    - A valid response consists of the HTTP header, containing the related directives, two newlines (`\r\n\r\n`), followed by the actual content (the file).
    - Sample answers can be found in the parser test file or in the provided sample.
    - You can use predefined request directives such as `Date`, `Last-Modified`, etc.
        - The `Content-Length` directive **must** specify the size of the HTTP content (actual data) in bytes.
        - The `Connection` directive **must** be initialized to `close`.
- The port on which the web server listens for connections is defined within the assignment header: the `AWS_LISTEN_PORT` macro.
- The root directory relative to which the resources/files are searched is defined within the assignment header as the `AWS_DOCUMENT_ROOT` macro.

### HTTP Parser

The clients and server will communicate using the HTTP protocol.
For parsing HTTP requests from clients it is recommended using [this HTTP parser](https://github.com/nodejs/http-parser), also available here' [http-parser](./skel/http-parser).
It will be needed to use a callback to get the path to the local resource requested by the client.
Find a simplified example of using the parser in the [samples directory](./skel/http-parser/samples/).


## Resources

- [sendfile](https://man7.org/linux/man-pages/man2/sendfile.2.html)

- [io_setup & friends](https://man7.org/linux/man-pages/man2/io_setup.2.html)

- [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html)
