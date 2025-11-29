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

struct server {
	int sockfd;                     // server socket
	struct sockaddr_in addr;        // server address
	char topic[MAX_USERNAME_LEN];   // server topic
	int listen_port;			    // server listening port
	LIST_ENTRY(server) entries;     // BSD list linkage
};


LIST_HEAD(clientlist, client);
LIST_HEAD(serverlist, server);

static size_t safe_strnlen(const char *s, size_t max_len) {
    size_t i;
    for (i = 0; i < max_len && s[i] != '\0'; i++);
    return i;
}


void broadcast_serverlist(struct serverlist *servers, int client_sockfd) {
	struct server *s;
	char listbuf[MAX];
	listbuf[0] = '\0';
	int idx = 1;
	LIST_FOREACH(s, servers, entries) {
		char line[MAX];
		snprintf(line, sizeof(line), "%d. %s\n", idx++, s->topic);
		strncat(listbuf, line, MAX - safe_strnlen(listbuf, MAX) - 1);
	}

	if (idx == 1) {
		snprintf(listbuf, sizeof(listbuf), "No servers available.\n");
	}

	write(client_sockfd, listbuf, safe_strnlen(listbuf, MAX)); // send the list
}

int main(int argc, char **argv)
{
	struct clientlist clients;          // the head of the client list
	struct serverlist servers;          // the head of the server list
	LIST_INIT(&clients);
	LIST_INIT(&servers);

	//#region setup_listen_socket
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
	serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	printf("Server running on %s:%d\n", SERV_HOST_ADDR, SERV_TCP_PORT);

	listen(sockfd, 5);
	//#endregion setup_listen_socket

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
		struct client *c, *tmp_c;
		LIST_FOREACH(c, &clients, entries) {
			int clisockfd = c->sockfd;
    		if (clisockfd > 0) {          // sanity check (usually always > 0)
        		FD_SET(clisockfd, &readset);  // add to read set
				/* Compute max_fd as you go */
        		if (clisockfd > max_fd) {max_fd = clisockfd;}
			}
		}

		struct server *s, *tmp_s;
		LIST_FOREACH(s, &servers, entries) {
			FD_SET(s->sockfd, &readset);
			if (s->sockfd > max_fd) max_fd = s->sockfd;
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
					
					char typebuf[32] = {0};
					ssize_t typebytes = read(newsockfd, typebuf, sizeof(typebuf) - 1);
					if (typebytes <= 0) {
						fprintf(stderr, "%s:%d Error reading peer type\n", __FILE__, __LINE__);
						close(newsockfd);
						continue;
					}
					if (typebytes < sizeof(typebuf)) {
						typebuf[typebytes] = '\0'; // null-terminate
					} else {
						typebuf[sizeof(typebuf) - 1] = '\0'; // ensure null-termination
					}

					if (strncmp(typebuf, "SERVER", 6) == 0) {
						// --- Register new chatroom server ---
						s = malloc(sizeof(struct server));
						s->sockfd = newsockfd;
						s->addr = cli_addr;

						char *topic_start = typebuf + 7; // after "SERVER "


						// Check if this username is already taken
						// Check if first user
						int taken = 0;
						struct server *other;
						LIST_FOREACH(other, &servers, entries) {
							if (other != s && other->topic[0] != '\0') {
									char topic[MAX_USERNAME_LEN] = {0};
									if(sscanf(typebuf, "SERVER %23s %*d", topic) != 1) {
										fprintf(stderr, "Invalid handshake from chat server\n");
										write(newsockfd, "Invalid handshake from chat server.\0", 37);
										close(newsockfd);
										//free(s);
										break;
									}
									
								if (strncmp(other->topic, topic, MAX_USERNAME_LEN - 1) == 0) {
									taken = 1;
									break;
								}
							}
						}

						if (taken || topic_start[0] == '\0') {
							// Topic taken or invalid
							char buf[MAX] = {'\0'};
							snprintf(buf, MAX, "Username unavailable or invalid, try again:");
							fprintf(stderr, "%s", buf);
							write(newsockfd, buf, MAX);
							close(newsockfd);
							continue;
						}

						// typebuf contains: "SERVER <topic> <port>"
						char topic[MAX_USERNAME_LEN] = {0};
						int listen_port = 0;
						if (sscanf(typebuf, "SERVER %23s %d", topic, &listen_port) != 2) {
							fprintf(stderr, "Invalid handshake from chat server\n");
							close(newsockfd);
							continue;
						}
						strncpy(s->topic, topic, MAX_USERNAME_LEN-1);
						s->topic[MAX_USERNAME_LEN-1] = '\0';
						s->listen_port = listen_port;

						//char buf[MAX] = {'\0'};
						//snprintf(buf, MAX, "Welcome, chatroom server for topic '%s'!", s->topic);
						//write(newsockfd, buf, MAX);
						fprintf(stderr, "Server %s has registered. It's listening at %s:%d", s->topic, inet_ntoa(cli_addr.sin_addr), listen_port);
						fprintf(stderr, " Connected from %s\n", inet_ntoa(cli_addr.sin_addr));
						LIST_INSERT_HEAD(&servers, s, entries);
					} 
					else if (strncmp(typebuf, "CLIENT", 6) == 0) {
						// --- Register new user client ---
						int count = 0;
						LIST_FOREACH(c, &clients, entries) count++;

						if (count >= MAX_CLIENTS) {
							fprintf(stderr, "Maximum clients reached. Rejecting client %s\n", inet_ntoa(cli_addr.sin_addr));
							close(newsockfd);
							continue;  // skip the rest of this iteration
						}

						c = malloc(sizeof(struct client));
						c->sockfd = newsockfd;
						c->addr = cli_addr;
						c->nickname[0] = '\0';  // no nickname				
						LIST_INSERT_HEAD(&clients, c, entries);  // insert at the head
						printf("Added client %d from addr %s\n", c->sockfd, inet_ntoa(c->addr.sin_addr));
						broadcast_serverlist(&servers, newsockfd);
					}
					else {
						fprintf(stderr, "Unknown peer type from %s — closing\n", inet_ntoa(cli_addr.sin_addr));
						close(newsockfd);
					}
				}

			}

			LIST_FOREACH_SAFE(s, &servers, entries, tmp_s) {
				int serversockfd = s->sockfd;
				// if server has something to read (a disconnect in our case)
				if (FD_ISSET(serversockfd, &readset)) {
					char buf[MAX] = {'\0'};
					/* ONLY HANDLING DISCONNECTS */
					ssize_t nread = read(serversockfd, buf, MAX);
					printf("Read %zd bytes from server %d\n", nread, serversockfd);
					if (nread <= 0) {
						fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__);
						close (serversockfd);
						LIST_REMOVE(s, entries); // inside LIST_FOREACH_SAFE, so safe to remove
						free(s);
						continue;
				}
			}

			/* TODO: Check ALL your client sockets, e.g., using LIST_FOREACH */
			LIST_FOREACH_SAFE(c, &clients, entries, tmp_c) {

				int clisockfd = c->sockfd;

				/* Note that this is a seperate if, not an else if -- multiple sockets
				* may become ready */
				if (FD_ISSET(clisockfd, &readset)) {

					char buf[MAX] = {'\0'};
					ssize_t nread = read(clisockfd, buf, MAX);
					printf("Read %zd bytes from client %d\n", nread, clisockfd);
					if (nread <= 0) {
						fprintf(stderr, "%s:%d Error reading from client\n", __FILE__, __LINE__);
						close (clisockfd);
						LIST_REMOVE(c, entries); // inside LIST_FOREACH_SAFE, so safe to remove
						free(c);
						continue;
					}

					if (nread < MAX) buf[nread] = '\0';  // null-terminate the string
					else buf[MAX - 1] = '\0'; 			 // ensure null-termination

			        int server_count = 0;
			        LIST_FOREACH(s, &servers, entries) server_count++;
        			int choice = buf[0] - '0';  // convert char '1', '2', ... to int
					if (choice < 1 || choice > server_count) {
						// Invalid choice
						char msg[MAX] = {'\0'};
						snprintf(msg, MAX, "Invalid server choice. Please try again:\n");
						write(clisockfd, msg, MAX);
						broadcast_serverlist(&servers, clisockfd);
						continue;
					}

					// Valid choice, find the server
					char msg[MAX] = {'\0'};
					//snprintf(msg, MAX, "Connecting you to server %d...\n", choice);
					//write(clisockfd, msg, MAX);

					struct server *selected = NULL;

					int idx = 1;
					LIST_FOREACH(s, &servers, entries) {
						if (idx == choice) {
							selected = s;
							break;
						}
						idx++;
					}
					if (!selected) {
						fprintf(stderr, "Error: chosen server not found (should never happen)\n");
						continue;
					}
					
					char ip[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(selected->addr.sin_addr), ip, INET_ADDRSTRLEN);
					int port = selected->listen_port;

					fprintf(stderr, "Client %d chose server %d. (%s:%d)\n", clisockfd, choice, ip, port);


					snprintf(msg, MAX, "SERVER_INFO %s %d\n", ip, port);
					write(clisockfd, msg, MAX);

					close (clisockfd);
					LIST_REMOVE(c, entries); // inside LIST_FOREACH_SAFE, so safe to remove
					free(c);
					fprintf(stderr, "Disconnected client %d after sending server info\n", clisockfd);
					continue;	
				}
			}
		}
		}
		else {
			/* Handle select errors */
		}
	}
}
