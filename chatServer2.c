#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h> // for BSD linked list macros
#include "inet.h"
#include "common.h"

#define MAX_USERNAME_LEN 24

#define LIST_FOREACH_SAFE(var, head, field, tvar) \
    for ((var) = LIST_FIRST((head)); \
         (var) && ((tvar) = LIST_NEXT((var), field), 1); \
         (var) = (tvar))

struct client {
    int sockfd;                     // client socket
    struct sockaddr_in addr;        // client address
	char nickname[MAX_USERNAME_LEN];// client nickname
    LIST_ENTRY(client) entries;     // BSD list linkage
};

LIST_HEAD(clientlist, client);


void broadcast_message(struct clientlist *clients, int sender_sockfd, const char *message) {
	struct client *c;
	LIST_FOREACH(c, clients, entries) {
		if (c->sockfd != sender_sockfd) { // Don't send the message back to the sender
			write(c->sockfd, message, MAX);
		}
	}
}

int connect_to_directory(const char *server_name, int port) {
    int sockfd;
    struct sockaddr_in dir_addr;
    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = htonl(INADDR_ANY); // inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port = htons(SERV_TCP_PORT);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("connect to directory server");
        close(sockfd);
        return -1;
    }

    // Send handshake: "SERVER <server_name>"
    char handshake[MAX];
    snprintf(handshake, sizeof(handshake), "SERVER %s %d", server_name, port);
    if (write(sockfd, handshake, strlen(handshake)) < 0) {
        perror("handshake failed");
        close(sockfd);
        return -1;
    }

    return sockfd; // idle connection
}

int main(int argc, char **argv)
{
	if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_name> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }
	const char *server_name = argv[1];
    int port = atoi(argv[2]);


	struct clientlist clients;          // the head of the client list
	LIST_INIT(&clients);


	int sockfd;			/* Listening socket */
	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDRR option to prevent address in use errors (modified from: "Hands-On Network
* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	serv_addr.sin_port			= htons(port);					/* parameter */

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}


	printf("Server running on %s:%d\n", SERV_HOST_ADDR, port);
	listen(sockfd, MAX_CLIENTS);

	int dir_sock = connect_to_directory(server_name, port);
	if (dir_sock < 0) {
        fprintf(stderr, "Failed to register with directory server.\n");
		close(sockfd);
		close(dir_sock);
		return EXIT_FAILURE;
    } else {
        printf("Connected to directory server at %s:%d\n", SERV_HOST_ADDR, SERV_TCP_PORT);
        // dir_sock sits idle
    }

	for (;;) {
		// int clisockfd;		/* EXAMPLE ONLY! */

		/* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		/* We won't write to a listening socket so no need to add it to the writeset */
		int max_fd = sockfd;

		/* FIXME: Populate readset with ALL your client sockets here,
		 * e.g., using LIST_FOREACH */
		/* clisockfd is used as an example socket -- we never populated it so it's invalid */		
		struct client *c, *tmp;
		LIST_FOREACH(c, &clients, entries) {
			int clisockfd = c->sockfd;
    		if (clisockfd > 0) {          // sanity check (usually always > 0)
        		FD_SET(clisockfd, &readset);  // add to read set
				/* Compute max_fd as you go */
        		if (clisockfd > max_fd) {max_fd = clisockfd;}
			}
		}


		if (select(max_fd+1, &readset, NULL, NULL, NULL) > 0) {

			/* Check to see if our listening socket has a pending connection */
			if (FD_ISSET(sockfd, &readset)) {
				/* Accept a new connection request */
				socklen_t clilen = sizeof(cli_addr);
				int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");
					close (newsockfd);
					continue;
					//close(sockfd);
					//return EXIT_FAILURE;
				} else {
					/* FIXME: Add newsockfd to your list of clients -- but no nickname yet */
					/* We can't immediately read(newsockfd) because we haven't asked
					* select whether it's ready for reading yet */
					
					int count = 0;
					LIST_FOREACH(c, &clients, entries) {
						count++;
					}

					if (count >= MAX_CLIENTS) {
						fprintf(stderr, "Maximum clients reached. Rejecting client %s\n", inet_ntoa(cli_addr.sin_addr));
						close(newsockfd);
						continue;  // skip the rest of this iteration
					}

					/*struct client * */c = malloc(sizeof(struct client));
					c->sockfd = newsockfd;
					c->addr = cli_addr;
					c->nickname[0] = '\0';  // no nickname yet
					

					LIST_INSERT_HEAD(&clients, c, entries);  // insert at the head
					printf("Added client %d from addr %s\n", c->sockfd, inet_ntoa(c->addr.sin_addr));
				}

			}

			/* TODO: Check ALL your client sockets, e.g., using LIST_FOREACH */
			LIST_FOREACH_SAFE(c, &clients, entries, tmp) {
				/*
				if (FD_ISSET(c->sockfd, &readset)) {      // client ready
					char s[MAX] = {'\0'};
					int n = read(c->sockfd, s, sizeof(s)-1);

					if (n <= 0) {                          // disconnected or error
						printf("Client %d disconnected\n", c->sockfd);
						close(c->sockfd);
						LIST_REMOVE(c, entries);
						free(c);
					} else {
						s[n] = '\0';
						printf("Received from client %d: %s\n", c->sockfd, s);
						write(c->sockfd, s, n);       // optional echo
					}
				}
				*/

				int clisockfd = c->sockfd;

				/* clisockfd is used as an example socket -- we never populated it so
				* it's invalid */
				//int clisockfd;
				/* Note that this is a seperate if, not an else if -- multiple sockets
				* may become ready */
				if (FD_ISSET(clisockfd, &readset)) {

					/* FIXME: Modify the logic */


					char s[MAX] = {'\0'};

					/* Read the request from the client */
					/* FIXME: This may block forever since we haven't asked select
						whether clisockfd is ready */
					ssize_t nread = read(clisockfd, s, MAX);
					printf("Read %zd bytes from client %d\n", nread, clisockfd);
					if (nread <= 0) {
						/* Not every error is fatal. Check the return value and act accordingly. */
						fprintf(stderr, "%s:%d Error reading from client\n", __FILE__, __LINE__);
						
						char message[MAX];
						snprintf(message, sizeof(message), "<Server> %s has left the chat.", c->nickname);
						broadcast_message(&clients, clisockfd, message);

						close (clisockfd);
						LIST_REMOVE(c, entries); // inside LIST_FOREACH_SAFE, so safe to remove
						free(c);
						continue;
						//return EXIT_FAILURE;
					}

					if (nread < MAX) s[nread] = '\0';  // null-terminate the string
					else s[MAX - 1] = '\0'; // ensure null-termination

					if (c->nickname[0] == '\0') {

						// Trim newline if present
						// Safe to ingnore warning because fmt is not user-controlled
						char fmt[20];
						snprintf(fmt, sizeof(fmt), "%%%d[^\n]", MAX - 1);
						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
						sscanf(s, fmt, s);
						#pragma GCC diagnostic pop


						// Check if this username is already taken
						// Check if first user
						int taken = 0;
						int alone = 1;
						struct client *other;
						LIST_FOREACH(other, &clients, entries) {
							if (other != c && other->nickname[0] != '\0') {
								if (strncmp(other->nickname, s, MAX_USERNAME_LEN - 1) == 0) {
									taken = 1;
									break;
								}
								alone = 0;
							}
						}

						if (!taken && s[0] != '\0') {
							// Username available, assign it
							// strncpy(c->nickname, s, MAX_USERNAME_LEN - 1);
							snprintf(c->nickname, MAX_USERNAME_LEN, "%.*s", MAX_USERNAME_LEN - 1, s);
							c->nickname[MAX_USERNAME_LEN-1] = '\0';
							if (alone) {
								snprintf(s, MAX, "Welcome, %s! You are the first user here.", c->nickname);
							} else {
								snprintf(s, MAX, "Welcome, %s! There are other users here.", c->nickname);
							}
							write(clisockfd, s, MAX);
							char message[MAX];
							snprintf(message, MAX, "<Server> %s has joined the chat.", c->nickname);
							broadcast_message(&clients, clisockfd, message);
							continue; // Done processing this client
						} else {
							// Username taken or invalid
							snprintf(s, MAX, "Username unavailable or invalid, try again:");
							write(clisockfd, s, MAX);
							continue; // Ask again
						}

					} else{

						/* Generate an appropriate reply based on the first character of the client's message */

						if (s[0] == /* FIXME */ true) {
							/* YOUR LOGIC GOES HERE */
						}
						else if (s[0] == /* FIXME */ true) {
							/* YOUR LOGIC GOES HERE */
						}
						/* YOUR LOGIC GOES HERE */
						else {
							//snprintf(s, MAX, "Invalid request\n\0");
						}
						
						char message[MAX + MAX_USERNAME_LEN + 4];
						snprintf(message, sizeof(message), "[%s] %s", c->nickname, s);

						// if message is too long, broadcast_message will truncate it
						// to MAX length, which is fine
						broadcast_message(&clients, clisockfd, message);

						//fprintf(stderr, s);
						/* Send the reply to the client */
						//write(clisockfd, s, MAX);
					}
				}
			}
		}
		else {
			/* Handle select errors */
		}
	}
}
