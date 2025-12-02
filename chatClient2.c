#define _GNU_SOURCE
#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int connect_to_server(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("can't connect to server: socket");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int main()
{
	char buf[MAX] = {'\0'};

    int dir_sock;

    /* --- Connect to directory server --- */
    dir_sock = connect_to_server(SERV_HOST_ADDR, SERV_TCP_PORT);
    if (dir_sock < 0) return EXIT_FAILURE;

    fprintf(stderr, "Connected to directory server at %s:%d\n", SERV_HOST_ADDR, SERV_TCP_PORT);
	
    /* --- Send initial CLIENT handshake --- */
    char handshake[MAX] = {0}; 
    snprintf(handshake, sizeof(handshake), "CLIENT\n");
    if (write(dir_sock, handshake, MAX) < 0) {
        perror("Error sending CLIENT handshake");
        close(dir_sock);
        return EXIT_FAILURE;
    }

    fd_set readset;
    struct timeval wait_time;
    int sockfd = -1;
    char server_ip[INET_ADDRSTRLEN];
    int server_port;

	while (1) {
        /* Wait for response from directory server */
        FD_ZERO(&readset);
        FD_SET(dir_sock, &readset);
        wait_time.tv_sec = 5;
        wait_time.tv_usec = 0;

        int n = select(dir_sock + 1, &readset, NULL, NULL, &wait_time);
        if (n <= 0) {
            fprintf(stderr, "Timeout waiting for directory server\n");
            close(dir_sock);
            return EXIT_FAILURE;
        }

        if (FD_ISSET(dir_sock, &readset)) {
            ssize_t nread = read(dir_sock, buf, MAX - 1);
            if (nread <= 0) {
                fprintf(stderr, "Directory server closed connection\n");
                close(dir_sock);
                return EXIT_FAILURE;
            }
            buf[nread] = '\0';

            /* Check if server accepted client */
            if (strncmp(buf, "SERVER_INFO ", 12) == 0) {
                /* Parse IP and PORT */
                if (sscanf(buf + 12, "%63s %d", server_ip, &server_port) != 2) {
                    fprintf(stderr, "Malformed SERVER_INFO: %s\n", buf);
                    close(dir_sock);
                    return EXIT_FAILURE;
                }

                /* Connect to selected server */
                sockfd = connect_to_server(server_ip, server_port);
                if (sockfd < 0) {
                    fprintf(stderr, "Failed to connect to server %s:%d\n", server_ip, server_port);
                    close(dir_sock);
                    return EXIT_FAILURE;
                }

                fprintf(stderr, "Connected to server %s:%d\n", server_ip, server_port);
                break; // Proceed to username input
            } else {
                /* Directory server sent a list or rejection, display to user */
                fprintf(stderr, "%s\n", buf);

				if (strncmp(buf, "No servers available.", 21) == 0) {
					fprintf(stderr, "Exiting due to no available servers.\n");
					close(dir_sock);
					return EXIT_FAILURE;
				}
                fprintf(stderr, "Select a server number: ");
                fflush(stderr);

                /* Read user input */
                if (fgets(buf, MAX, stdin)) {
                    
                    if (strnlen(buf, MAX) > 0 && buf[strnlen(buf, MAX) - 1] == '\n') {
                        buf[strnlen(buf, MAX) - 1] = '\0'; // Remove newline
                    }

                    write(dir_sock, buf, MAX);
                } else {
					fprintf(stderr, "Error reading user input\n");
					close(dir_sock);
					return EXIT_FAILURE;
				}
            }
        }
    }

	
	fprintf(stderr, "Enter your username:\n");

	fprintf(stderr, "> "); // Prompt for input
	fflush(stderr);

	for(;;) {

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);
			wait_time.tv_sec=5;
			wait_time.tv_usec=0; // Wait time is 5 seconds.

		int n;
		if ((n=select(sockfd+1, &readset, NULL, NULL, &wait_time)) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				/* Read a line from stdin */
				if (fgets(buf, MAX, stdin)) {

					// Trim newline if present
					char fmt[20];
					snprintf(fmt, sizeof(fmt), "%%%d[^\n]", MAX - 1);
					#pragma GCC diagnostic push
					#pragma GCC diagnostic ignored "-Wformat-nonliteral"
					sscanf(buf, fmt, buf);
					#pragma GCC diagnostic pop

					/* Send the user's message to the server */
					write(sockfd, buf, MAX);
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
				}
				fprintf(stderr, "> "); // Prompt for input
				fflush(stderr);
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
				ssize_t nread = read(sockfd, buf, MAX);
				if (nread <= 0) {
					fprintf(stderr, "\r\033[K");  // Clear the current line
					fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__); //DEBUG
					close(sockfd);
					return EXIT_FAILURE;
				} else {
					//fprintf(stderr, "%s:%d Read %zd bytes from server: %s\n", __FILE__, __LINE__, nread, s); //DEBUG
					if (nread < MAX) buf[nread] = '\0';  // null-terminate the string
					else buf[MAX - 1] = '\0'; // ensure null-termination
					//fprintf(stderr, "%s:%d Read %zd bytes from server:\n", __FILE__, __LINE__, nread); //DEBUG

					fprintf(stderr, "\r\033[K");  // Clear the current line
					fprintf(stderr, "%s\n", buf); //DEBUG

					fprintf(stderr, "> "); // Prompt for input
					fflush(stderr);
				}
			}
		}
	}
	close(sockfd);
	close(dir_sock);
	// return or exit(0) is implied; no need to do anything because main() ends
}
