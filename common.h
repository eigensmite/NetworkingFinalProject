// Macros are unused because this is just a config file
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-macros"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX 100

#define MAX_USERNAME_LEN 24

#define MAX_CLIENTS 2
#define MAX_SERVERS 2

#pragma GCC diagnostic pop
