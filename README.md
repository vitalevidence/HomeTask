The code has many error-handling mechanisms, but many erroneous situations have not been thoroughly tested.
I thoroughly tested it with one client and ran it a few times without disconnections. All other scenarios are theoretical and have not been well-tested.

Verified with Valgrind for the absence of memory leaks and uninitialized memory access.

Tested with:
 fedora 41
 gcc version 14.3.1
 OpenSSL 3.2.4
 gtest 1.14.0

To build:
 Required openssl, gtest (with devel)
 cmake -B build .
 cd build 
 make

To run the simple test:
 ./demo.sh

To start the server:
 ./stx_recv --listen <PORT> --out <OUT_PATH>
 <PORT>: port for listening
 <OUT_PATH>: the path to storing files; should be writable and exists

To start client:
 ./stx_send 127.0.0.1 <PORT> <IN_FILE> [<OUT_NAME>]
 <PORT>: port for connecting
 <IN_FILE>: input file name
 <OUT_NAME>: name for storing on the server (only name, without path!). If omitted, then the name of <IN_FILE> will be used
 127.0.0.1: instead, this IP may be any arbitrary (but not tested)
