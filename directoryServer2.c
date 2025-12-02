#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h> // for BSD linked list macros
#include "inet.h"
#include "common.h"

#define LIST_FOREACH_SAFE(var, head, field, tvar) \
    for ((var) = LIST_FIRST((head)); \
         (var) && ((tvar) = LIST_NEXT((var), field), 1); \
         (var) = (tvar))

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))

/* struct client {
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
*/

struct outmsg {
	size_t len;       // total bytes
    size_t sent;      // bytes already sent (for partial writes)
	char* data;       // full message text
    TAILQ_ENTRY(outmsg) entries;
};

struct staged_connection {
	int sockfd;                     	// client socket
	struct sockaddr_in addr;        	// client address
	char inbuf[MAX];			  		// input buffer
	char* inptr;                    	// length of data in input buffer (bytes)
	LIST_ENTRY(staged_connection) entries;  // BSD list linkage
};

struct client {
    int sockfd;                     	// client socket
    struct sockaddr_in addr;        	// client address
	char nickname[MAX_USERNAME_LEN];	// client nickname
	char redirecting;					// whether client is being redirected
	TAILQ_HEAD(, outmsg) msgq;  		// message queue
	char inbuf[MAX];			  		// input buffer
	char* inptr;                    	// length of data in input buffer (bytes)
    LIST_ENTRY(client) client_entries;  // BSD list linkage
};

struct server {
    int sockfd;                     	// server socket
    struct sockaddr_in addr;        	// server address
	int listen_port;			    	// server listening port
	char topic[MAX_USERNAME_LEN];		// server topic
	// TAILQ_HEAD(, outmsg) msgq;  		// message queue
	// char inbuf[MAX];			  		// input buffer
	// char* inptr;                    	// length of data in input buffer (bytes)
    LIST_ENTRY(server) server_entries;  // BSD list linkage
};

LIST_HEAD(staged_connection_list, staged_connection);
LIST_HEAD(clientlist, client);
LIST_HEAD(serverlist, server);


void broadcast_serverlist(struct serverlist *servers, struct client *c);
static void remove_client(struct clientlist *clients, struct client *c);
static void remove_staged_connection(struct staged_connection_list *staged_conns, struct staged_connection *staged);
static void remove_server(struct serverlist *servers, struct server *s);
static void queue_message(struct client *c, const char *msg);

int main(int argc, char **argv)
{
	struct clientlist clients;          // the head of the client list
	struct serverlist servers;          // the head of the server list
	struct staged_connection_list staged_conns; // the head of the staged connections list
	LIST_INIT(&clients);
	LIST_INIT(&servers);
	LIST_INIT(&staged_conns);

	//#region setup_listen_socket
	int sockfd;			/* Listening socket */
	struct sockaddr_in cli_addr, serv_addr;

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
		close(sockfd); // unncessary, but good practice
		return EXIT_FAILURE;
	}

	printf("Server running on %s:%d\n", SERV_HOST_ADDR, SERV_TCP_PORT);

	listen(sockfd, MAX_CLIENTS + MAX_SERVERS);
	//#endregion setup_listen_socket

	for (;;) {
		
		fd_set readset, writeset;

		/* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_ZERO(&writeset);

		// Add listening socket to read set
		FD_SET(sockfd, &readset);
		int max_fd = sockfd;

		/* FIXME: Populate readset with ALL your client sockets here,
		 * e.g., using LIST_FOREACH */
		/* clisockfd is used as an example socket -- we never populated it so it's invalid */		
		struct client *c, *tmp_c;
		LIST_FOREACH_SAFE(c, &clients, client_entries, tmp_c) {
			/*	int clisockfd = c->sockfd;
    		 if (clisockfd > 0) {          // sanity check (usually always > 0)
        		FD_SET(clisockfd, &readset);  // add to read set
				// Compute max_fd as you go 
        		if (clisockfd > max_fd) {max_fd = clisockfd;}
			 }	*/
			if (c->sockfd > 0) {          			// sanity check (usually always > 0)
        		FD_SET(c->sockfd, &readset);  		// add to read set
				if (!TAILQ_EMPTY(&c->msgq)) {		// has data to write
					FD_SET(c->sockfd, &writeset); 	// add to write set
				}
				/* Update max_fd */
        		if (c->sockfd > max_fd) max_fd = c->sockfd;
			}
		}

		struct server *s, *tmp_s;
		LIST_FOREACH_SAFE(s, &servers, server_entries, tmp_s) {
			if (s->sockfd > 0) {          			// sanity check (usually always > 0)
				FD_SET(s->sockfd, &readset);  		// add to read set
				//if (!TAILQ_EMPTY(&s->msgq)) {		// has data to write
				//	FD_SET(s->sockfd, &writeset); 	// add to write set
				//}
				/* Update max_fd */
				if (s->sockfd > max_fd) max_fd = s->sockfd;
			}
		}

		struct staged_connection *staged, *tmp_staged;
		LIST_FOREACH_SAFE(staged, &staged_conns, entries, tmp_staged) {
			if (staged->sockfd > 0) {          			// sanity check (usually always > 0)
				FD_SET(staged->sockfd, &readset);  		// add to read set
				/* Update max_fd */
				if (staged->sockfd > max_fd) max_fd = staged->sockfd;
			}
		}

		int sel = select(max_fd+1, &readset, &writeset, NULL, NULL);
		if (sel < 0) {
			if (errno == EINTR) continue;
			perror("select");
			close(sockfd);
			return EXIT_FAILURE;
		} else if (sel == 0) {
			continue; /* shouldn't happen with NULL timeout */
		} else if (sel > 0) {

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

					/* Set non-blocking on this client socket */
					if (fcntl(newsockfd, F_SETFL, O_NONBLOCK) < 0) {
						perror("fcntl staged_connection O_NONBLOCK");
						close (newsockfd);
						continue;
					}

					struct staged_connection *new_staged = malloc(sizeof(struct staged_connection));
					if (!new_staged) {
						fprintf(stderr, "server: out of memory\n");
						close (newsockfd);
						continue;
					}

					new_staged->sockfd = newsockfd; 	// set client socket
					new_staged->addr = cli_addr;		// set client address
					new_staged->inbuf[0] = '\0';     // initialize input buffer
					new_staged->inptr = new_staged->inbuf;    // set input pointer to start of

					LIST_INSERT_HEAD(&staged_conns, new_staged, entries);  // insert at the head
					printf("Added staged connection %d from addr %s\n", new_staged->sockfd, inet_ntoa(new_staged->addr.sin_addr));
				}

			}

			LIST_FOREACH_SAFE(staged, &staged_conns, entries, tmp_staged) {

				int stagedsockfd = staged->sockfd;
				// if staged connection has something to read
				if (FD_ISSET(stagedsockfd, &readset)) {

					ssize_t typebytes = read(stagedsockfd, staged->inptr, &(staged->inbuf[MAX]) - staged->inptr); //MAX - 1 reads 99 bytes, so MAX is correct
					if (typebytes <= 0) {
						fprintf(stderr, "%s:%d Error reading peer type %s\n", __FILE__, __LINE__, staged->inptr);
						remove_staged_connection(&staged_conns, staged);
						continue;
					}

					staged->inptr += typebytes;

					if ((staged->inptr < &(staged->inbuf[MAX]))) continue; // not a full message yet

					staged->inbuf[MAX - 1] = '\0';   // ensure null-termination
					staged->inptr = staged->inbuf; // reset input pointer for next read

					if (strncmp(staged->inptr, "SERVER", 6) == 0) {
						// --- Register new chatroom server ---

						int count = 0;
						LIST_FOREACH_SAFE(s, &servers, server_entries, tmp_s) count++;

						if (count >= MAX_SERVERS) {
							fprintf(stderr, "Maximum servers reached. Rejecting server %s\n", inet_ntoa(cli_addr.sin_addr));
							remove_staged_connection(&staged_conns, staged);
							continue;  // skip the rest of this iteration
						}

						// Check if this username is already taken
						// Check if first user
						int taken = 0;
						struct server *other;
						LIST_FOREACH_SAFE(other, &servers, server_entries, tmp_s) {
							if (/*other != s &&*/ other->topic[0] != '\0') {
									char topic[MAX_USERNAME_LEN] = {0};
									if(sscanf(staged->inptr, "SERVER %*d %23[^\n]", topic) != 1) {
										fprintf(stderr, "Invalid handshake from chat server\n");
										remove_staged_connection(&staged_conns, staged);
										break;
									}
									
								if (strncmp(other->topic, topic, MAX_USERNAME_LEN - 1) == 0) {
									taken = 1;
									break;
								}
							}
						}

						if (taken /* || topic_start[0] == '\0' */ ) {
							// Topic taken or invalid
							char buf[MAX] = {'\0'};
							snprintf(buf, MAX, "Username unavailable or invalid, try again:");
							fprintf(stderr, "%s", buf);
							//write(newsockfd, buf, MAX);
							remove_staged_connection(&staged_conns, staged);
							continue;
						}

						// staged->inptr contains: "SERVER <topic> <port>"
						char topic[MAX_USERNAME_LEN] = {0};
						int listen_port = 0;
						if (sscanf(staged->inptr, "SERVER %d %23[^\n]", &listen_port, topic) != 2) {
							fprintf(stderr, "Invalid handshake from chat server\n");
							remove_staged_connection(&staged_conns, staged);
							continue;
						}


						s = malloc(sizeof(struct server));
						s->sockfd = staged->sockfd;
						s->addr = staged->addr;

						//str ncpy(s->topic, topic, MAX_USERNAME_LEN-1);
						sscanf(topic, "%23[^\n]", s->topic);
						
						s->topic[MAX_USERNAME_LEN-1] = '\0';
						s->listen_port = listen_port;

						//char buf[MAX] = {'\0'};
						//snprintf(buf, MAX, "Welcome, chatroom server for topic '%s'!", s->topic);
						//write(newsockfd, buf, MAX);
						fprintf(stderr, "Server %s has registered. It's listening at %s:%d", s->topic, inet_ntoa(cli_addr.sin_addr), listen_port);
						fprintf(stderr, " Connected from %s\n", inet_ntoa(cli_addr.sin_addr));
						LIST_INSERT_HEAD(&servers, s, server_entries);

						free(staged);
						LIST_REMOVE(staged, entries);
					} 
					else if (strncmp(staged->inptr, "CLIENT", 6) == 0) {
						// --- Register new user client ---
						int count = 0;
						LIST_FOREACH_SAFE(c, &clients, client_entries, tmp_c) count++;

						if (count >= MAX_CLIENTS) {
							fprintf(stderr, "Maximum clients reached. Rejecting client %s\n", inet_ntoa(cli_addr.sin_addr));
							remove_staged_connection(&staged_conns, staged);
							continue;  // skip the rest of this iteration
						}

						c = malloc(sizeof(struct client));
						c->sockfd = staged->sockfd; 	// set client socket
						c->addr = staged->addr;		// set client address
						c->nickname[0] = '\0';  // no nickname		
						c->redirecting = 0; // not redirecting yet
						TAILQ_INIT(&c->msgq);	// initialize message queue
						c->inbuf[0] = '\0';     // initialize input buffer
						c->inptr = c->inbuf;    // set input pointer to start of

						LIST_INSERT_HEAD(&clients, c, client_entries);  // insert at the head
						printf("Added client %d from addr %s\n", c->sockfd, inet_ntoa(c->addr.sin_addr));
						broadcast_serverlist(&servers, c);

						free(staged);
						LIST_REMOVE(staged, entries);
					}
					else {
						fprintf(stderr, "Unknown peer type from %s — closing\n", inet_ntoa(cli_addr.sin_addr));
						remove_staged_connection(&staged_conns, staged);
					}
				}
			}

			// Check server sockets for disconnects
			LIST_FOREACH_SAFE(s, &servers, server_entries, tmp_s) {
				int serversockfd = s->sockfd;
				// if server has something to read (a disconnect in our case)
				if (FD_ISSET(serversockfd, &readset)) {
					char buf[MAX] = {'\0'};
					/* ONLY HANDLING DISCONNECTS */
					ssize_t nread = read(serversockfd, buf, MAX);
					printf("Read %zd bytes from server %d\n", nread, serversockfd);
					if (nread == 0) {
						fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__);
						remove_server(&servers, s);
						continue;
					}
					else if (nread < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) continue; // try again later

						fprintf(stderr, "%s:%d Error reading from server %d: %s\n", __FILE__, __LINE__, serversockfd, strerror(errno));

						remove_server(&servers, s);
						continue;
					}
				}
			}

			/* TODO: Check ALL your client sockets, e.g., using LIST_FOREACH */
			LIST_FOREACH_SAFE(c, &clients, client_entries, tmp_c) {

				int clisockfd = c->sockfd;

				/* Note that this is a seperate if, not an else if -- multiple sockets
				* may become ready */
				if (FD_ISSET(clisockfd, &readset)) {

					ssize_t nread = read(clisockfd, c->inptr, &(c->inbuf[MAX]) - c->inptr); //MAX - 1 reads 99 bytes, so MAX is correct
					printf("Read %zd bytes from client %d\n", nread, clisockfd);


					// IF READ LENGTH IS ZERO, CLIENT DISCONNECTS. THIS CAN HAPPEN INADVERTENTLY IF 
					// THE FORMULA FOR READING IS WRONG, SINCE ITERATION CONTINUES IF POINTER ISN'T
					// AT END OF BUFFER. AS OF NOW, &(c->inbuf[MAX]) - c->inptr IS THE CORRECT FORMULA.
					if (nread == 0) { 
						/* orderly shutdown by client */
						remove_client(&clients, c);
						//continue; /* c is freed - continue with next in loop */
					}
					else if (nread < 0) {

						if (errno == EAGAIN || errno == EWOULDBLOCK) continue; // try again later

						fprintf(stderr, "%s:%d Error reading from client %d: %s\n", __FILE__, __LINE__, clisockfd, strerror(errno));

						remove_client(&clients, c);
						//continue;
					} else /* if (nread > 0) */ {

						c->inptr += nread; // advance input pointer
						if ((c->inptr < &(c->inbuf[MAX]))) continue; // not full message yet

						c->inbuf[MAX - 1] = '\0';   // ensure null-termination
						c->inptr = c->inbuf; // reset input pointer for next read

						int server_count = 0;
						LIST_FOREACH_SAFE(s, &servers, server_entries, tmp_s) server_count++;
						int choice = c->inbuf[0] - '0';  // convert char '1', '2', ... to int
						if (choice < 1 || choice > server_count) {
							// Invalid choice
							char msg[MAX] = {'\0'};
							snprintf(msg, MAX, "Invalid server choice. Please try again:\n");
							queue_message(c, msg);
							//write(clisockfd, msg, MAX);
							broadcast_serverlist(&servers, c);
							continue;
						}

						// Valid choice, find the server
						char msg[MAX] = {'\0'};
						//snprintf(msg, MAX, "Connecting you to server %d...\n", choice);
						//write(clisockfd, msg, MAX);

						struct server *selected = NULL;

						int idx = 1;
						LIST_FOREACH_SAFE(s, &servers, server_entries, tmp_s) {
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
						
						c->redirecting = 1;
						queue_message(c, msg);
						//write(clisockfd, msg, MAX);

						//remove_client(&clients, c);

						fprintf(stderr, "Disconnected client %d after sending server info\n", clisockfd);
						continue;	
					}
				}

				/* Handle writable client sockets */
				if (FD_ISSET(clisockfd, &writeset)) {
					struct outmsg *m = TAILQ_FIRST(&c->msgq);
					if (!m) continue; // no messages queued

					size_t remaining = m->len - m->sent;

					ssize_t nwrite = write(clisockfd, m->data + m->sent, remaining); // can probably write as MAX FIXME
					if (nwrite > 0) {
						m->sent += nwrite;
						if (m->sent == m->len) {
							TAILQ_REMOVE(&c->msgq, m, entries); // sends only one message from queue per iteration, should be fine (Euguene said)
							free(m->data);
							free(m);

							if (c->redirecting && TAILQ_EMPTY(&c->msgq)) {
								// Client has been sent the server info, disconnect them
								remove_client(&clients, c);
							}
						}
					} else if (nwrite < 0) {
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							// try later
						} else {
							fprintf(stderr, "Error writing to client %d: %s\n", clisockfd, strerror(errno));
							remove_client(&clients, c);
							continue;
						}
					}
				} 


			} /*     LIST_FOREACH_SAFE */
		}
	} /*                  for (;;) */
}


void broadcast_serverlist(struct serverlist *servers, struct client *c) {
	struct server *s, *tmp_s;
	char listbuf[MAX];
	listbuf[0] = '\0';
	int idx = 1;
	LIST_FOREACH_SAFE(s, servers, server_entries, tmp_s) {
		char line[MAX];
		snprintf(line, sizeof(line), "%d. %s\n", idx++, s->topic);
		strncat(listbuf, line, MAX - strnlen(listbuf, MAX) - 1);
	}

	if (idx == 1) {
		snprintf(listbuf, sizeof(listbuf), "No servers available.\n");
	}

	//write(client_sockfd, listbuf, strnlen(listbuf, MAX)); // send the list
	queue_message(c, listbuf);
	
}

static void queue_message(struct client *c, const char *msg) {
	size_t mlen = strnlen(msg, MAX);
    if (mlen == 0) return;

    struct outmsg *m = malloc(sizeof(*m));
    if (!m) {
		fprintf(stderr, "can't malloc new outmsg struct, server: out of memory\n");
		return;
	}

	m->data = malloc(mlen + 1);
    if (!m->data) {
		fprintf(stderr, "can't malloc new outmsg data, server: out of memory\n");
        free(m);
        return;
    }

	//memcpy(m->data, msg, mlen);
    //m->data[mlen] = '\0';
	snprintf(m->data, mlen + 1, "%s", msg); // ensure null-termination

    m->len = mlen;
    m->sent = 0;

	TAILQ_INSERT_TAIL(&c->msgq, m, entries);
}


static void remove_client(struct clientlist *clients, struct client *c) {
    if (clients && c) {
		printf("Removing client %d (%s)\n", c->sockfd, c->nickname);

		struct outmsg *m, *tmp;
		TAILQ_FOREACH_SAFE(m, &c->msgq, entries, tmp) {
			TAILQ_REMOVE(&c->msgq, m, entries);
			free(m->data);
			free(m);
		}

		close(c->sockfd);
		LIST_REMOVE(c, client_entries);
		free(c);
	}
}

static void remove_server(struct serverlist *servers, struct server *s) {
	if (servers && s) {
		printf("Removing server %d (%s)\n", s->sockfd, s->topic);

		close(s->sockfd);
		LIST_REMOVE(s, server_entries);
		free(s);
	}
}

static void remove_staged_connection(struct staged_connection_list *staged_conns, struct staged_connection *staged) {
	if (staged_conns && staged) {
		printf("Removing staged connection %d\n", staged->sockfd);

		close(staged->sockfd);
		LIST_REMOVE(staged, entries);
		free(staged);
	}
}