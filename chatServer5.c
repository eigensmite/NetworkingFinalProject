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
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#define CAFILE "certs/rootCA.crt" //TODO: Is this the correct file for authority?
#define BEOCATCERT "certs/beocat.crt"
#define BEOCATKEY "certs/beocatkey.pem"
#define FOOTBALLCERT "certs/football.crt"
#define FOOTBALLKEY "certs/footballkey.pem"
#define FRIENDSGIVINGCERT "certs/friendsgiving.crt"
#define FRIENDSGIVINGKEY "certs/friendsgivingkey.pem"
#define LOUNGECERT "certs/lounge.crt"
#define LOUNGEKEY "certs/loungekey.pem"

/* Code from GnuTLS documentation */

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd) \
	do {                  \
		rval = cmd;   \
	} while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

/* End code from GnuTLS documentation */

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
}; */

struct outmsg {
	size_t len;       // total bytes
    size_t sent;      // bytes already sent (for partial writes)
	char* data;       // full message text
    TAILQ_ENTRY(outmsg) entries;
};

struct client {
	gnutls_session_t session;
    int sockfd;                     	// client socket
    struct sockaddr_in addr;        	// client address
	char nickname[MAX_USERNAME_LEN];	// client nickname
	TAILQ_HEAD(, outmsg) msgq;  		// message queue
	char inbuf[MAX];			  		// input buffer
	char* inptr;                    	// length of data in input buffer (bytes)
    LIST_ENTRY(client) client_entries;  // BSD list linkage
};

LIST_HEAD(clientlist, client);

static int connect_to_directory(const char *server_name, int port, gnutls_session_t dir_session, gnutls_certificate_credentials_t x509_cred);

static void queue_message(struct client *c, const char *msg);
static void broadcast_message(struct clientlist *clients, int sender_sockfd, const char *message);
static void remove_client(struct clientlist *clients, struct client *c);

int main(int argc, char **argv)
{
	
	// Check command line arguments
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <server_name> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

	
	// Extract server name
	char server_name[MAX_USERNAME_LEN] = {0};
	snprintf(server_name, MAX_USERNAME_LEN, "%.*s", MAX_USERNAME_LEN - 1, argv[1]);
	printf("%.*s\n", MAX_USERNAME_LEN - 1, argv[1]);
	server_name[MAX_USERNAME_LEN - 1] = '\0';
	
	// Extract port number
    int port;
	if(sscanf(argv[2], "%d", &port) != 1) {
		fprintf(stderr, "Invalid port number: %s\n", argv[2]);
		return EXIT_FAILURE;
	}	
	
	/* init GnuTLS */
	
	gnutls_certificate_credentials_t x509_cred;
	
	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	//Set which chat server we are creating
	if(strncmp(server_name, "Beocat", MAX_USERNAME_LEN) == 0) {
		gnutls_certificate_set_x509_key_file(x509_cred, BEOCATCERT, BEOCATKEY, GNUTLS_X509_FMT_PEM);
	} else if(strncmp(server_name, "Football", MAX_USERNAME_LEN) == 0) {
		gnutls_certificate_set_x509_key_file(x509_cred, FOOTBALLCERT, FOOTBALLKEY, GNUTLS_X509_FMT_PEM);
	} else if(strncmp(server_name, "Friendsgiving", MAX_USERNAME_LEN) == 0) {
		gnutls_certificate_set_x509_key_file(x509_cred, FRIENDSGIVINGCERT, FRIENDSGIVINGKEY, GNUTLS_X509_FMT_PEM);
	} else if(strncmp(server_name, "Lounge", MAX_USERNAME_LEN) == 0) {
		gnutls_certificate_set_x509_key_file(x509_cred, LOUNGECERT, LOUNGEKEY, GNUTLS_X509_FMT_PEM);
	}

	//End init GnuTLS
	
	struct clientlist clients;          // the head of the client list
	LIST_INIT(&clients);
	
	
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
	serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);	/* arbitrary IP address */
	serv_addr.sin_port			= htons(port);			/* port from parameter */
	
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		close(sockfd); // unncessary, but good practice
		return EXIT_FAILURE;
	}
	
	printf("Server running on %s:%d\n", inet_ntoa(serv_addr.sin_addr), port);
	listen(sockfd, MAX_CLIENTS);

	gnutls_session_t dir_session;
	
	int dir_sock = connect_to_directory(server_name, port, dir_session, x509_cred);
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
		
		fd_set readset, writeset;
		int max_fd = -1;

		int ret = 0;

		/* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_ZERO(&writeset);

		// Add directory server socket
		FD_SET(dir_sock, &readset);
		if (dir_sock > max_fd) max_fd = dir_sock;

		// Add listening socket to read set
		FD_SET(sockfd, &readset);
		if (sockfd > max_fd) max_fd = sockfd;

		/* FIXME: Populate readset with ALL your client sockets here,
		 * e.g., using LIST_FOREACH_SAFE */
		/* clisockfd is used as an example socket -- we never populated it so it's invalid */		
		struct client *c, *tmp;
		LIST_FOREACH_SAFE(c, &clients, client_entries, tmp) {
    		if (c->sockfd > 0) {          			// sanity check (usually always > 0)
        		FD_SET(c->sockfd, &readset);  		// add to read set
				if (!TAILQ_EMPTY(&c->msgq)) {		// has data to write
					FD_SET(c->sockfd, &writeset); 	// add to write set
				}
				/* Update max_fd */
        		if (c->sockfd > max_fd) max_fd = c->sockfd;
			}
		}

		int sel = select(max_fd+1, &readset, &writeset, NULL, NULL);
		if (sel < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        } else if (sel == 0) continue; /* shouldn't happen with NULL timeout */


		// Check if directory server disconnected
		if (FD_ISSET(dir_sock, &readset)) { 
			// If directory server socket is readable 
			// (only possible if disconnected)
			fprintf(stderr, "Disconnected. Check dir server to see cause\n");
			fprintf(stderr, "1) non-unique topic,\n");
			fprintf(stderr, "2) maximum servers reached, or\n");
			fprintf(stderr, "3) directory server died\n");
			close(dir_sock);
			close(sockfd);
			return EXIT_FAILURE;
		}

		/* ADD NEW CLIENT (Check to see if our listening socket has a pending connection) */
		if (FD_ISSET(sockfd, &readset)) {
			/* Accept a new connection request */
			socklen_t clilen = sizeof(cli_addr);
			int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0) {
				perror("server: accept error");
				close (newsockfd); // CAN'T CLOSE INVALID SOCKET, but close() will return -1 for now and its fine (good template handling socket errors anyways)
				continue;				
			}

			/* Set non-blocking on this client socket */
			if (fcntl(newsockfd, F_SETFL, O_NONBLOCK) < 0) {
				perror("fcntl client O_NONBLOCK");
				close (newsockfd);
				continue;
			}
			
			int count = 0;
			LIST_FOREACH_SAFE(c, &clients, client_entries, tmp) { count++; }

			if (count >= MAX_CLIENTS) {
				fprintf(stderr, "Maximum clients reached. Rejecting client %s\n", inet_ntoa(cli_addr.sin_addr));
				close(newsockfd);
				continue;  // skip the rest of this iteration
			}

			c = malloc(sizeof(struct client));
			if (!c) {
				fprintf(stderr, "server: out of memory\n");
				close (newsockfd);
				continue;
			}

			//TLS Handshake with new client
			gnutls_session_t session;
			gnutls_init(&session, GNUTLS_SERVER); //TODO: Verify that this is correct
			gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
			gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
			gnutls_priority_set_direct(session, "NORMAL", NULL);
			gnutls_transport_set_int(session, newsockfd);

			LOOP_CHECK(ret, gnutls_handshake(session));
			if (ret < 0) {
				close(newsockfd);
				gnutls_deinit(session);
				fprintf(stderr, "*** handshake has failed (%s)\n\n", gnutls_strerror(ret));
				continue;
			}
			printf("- GNUTLS Handshake completed");

			c->session = session;	// set client tls session
			c->sockfd = newsockfd; 	// set client socket
			c->addr = cli_addr;		// set client address
			c->nickname[0] = '\0';  // no nickname yet
			//c->outbuf[0] = '\0';    // initialize output buffer
			//c->outlen = 0;          // empty output buffer
			TAILQ_INIT(&c->msgq);	// initialize message queue
			c->inbuf[0] = '\0';     // initialize input buffer
			c->inptr = c->inbuf;    // set input pointer to start of
			
			LIST_INSERT_HEAD(&clients, c, client_entries);  // insert at the head
			printf("Added client %d from addr %s\n", c->sockfd, inet_ntoa(c->addr.sin_addr));
		}

		/* PROCESS CLIENTS  */
		LIST_FOREACH_SAFE(c, &clients, client_entries, tmp) {

			int clisockfd = c->sockfd;

			/* READABLE? */
			if (FD_ISSET(clisockfd, &readset)) {

				/* Read the request from the client */
				//ssize_t nread = read(clisockfd, c->inptr, &(c->inbuf[MAX]) - c->inptr); //MAX - 1 reads 99 bytes, so MAX is correct
				LOOP_CHECK(ret, gnutls_record_recv(c->session, c->inptr, &(c->inbuf[MAX]) - c->inptr));
				printf("Read %zd bytes from client %d\n", ret, clisockfd);
				printf("Buffer now: %s\n", c->inbuf);
				// IF READ LENGTH IS ZERO, CLIENT DISCONNECTS. THIS CAN HAPPEN INADVERTENTLY IF 
				// THE FORMULA FOR READING fIS WRONG, SINCE ITERATION CONTINUES IF POINTER ISN'T
				// AT END OF BUFFER. AS OF NOW, &(c->inbuf[MAX]) - c->inptr IS THE CORRECT FORMULA.
				if (ret == 0) { 
                    /* orderly shutdown by client */
                    char msg[MAX];
                    snprintf(msg, sizeof(msg), "<Server> %s has left the chat.", c->nickname);
                    broadcast_message(&clients, clisockfd, msg);
                    remove_client(&clients, c);
                    //continue; /* c is freed - continue with next in loop */
				}
				else if (ret < 0) {
					//fprintf(stderr, "%s:%d Error reading from client\n", __FILE__, __LINE__);

					/* Not every error is fatal. Check the return value and act accordingly. */
					if (errno == EAGAIN || errno == EWOULDBLOCK) continue; // try again later

					/* real error reading from client */
					fprintf(stderr, "%s:%d Error reading from client %d: %s\n", __FILE__, __LINE__, clisockfd, strerror(errno));
					char msg[MAX];
					snprintf(msg, sizeof(msg), "<Server> %s has left the chat.", c->nickname);
					broadcast_message(&clients, clisockfd, msg);
					remove_client(&clients, c);
					//continue;
				}
				else /* if (nread > 0) */ {
				
					//fprintf(stderr, "Read %zd bytes from client %d\n", nread, clisockfd);
					c->inptr += ret; // advance input pointer
					//if (! (c->inptr >= &(c->inbuf[MAX]))) continue; // not a full message yet
					if ((c->inptr < &(c->inbuf[MAX]))) continue; // not a full message yet

					c->inbuf[MAX - 1] = '\0';   // ensure null-termination
					c->inptr = c->inbuf; // reset input pointer for next read

					//else inbuf[nread] = '\0';  // null-terminate the string

					if (c->nickname[0] == '\0') { // NICKNAME ASSIGNMENT

						// Check if this username is already taken
						// Check if first user
						int taken = 0;
						int alone = 1;
						struct client *other;
						LIST_FOREACH_SAFE(other, &clients, client_entries, tmp) {
							if (other != c && other->nickname[0] != '\0') {
								if (strncmp(other->nickname, c->inbuf, MAX_USERNAME_LEN - 1) == 0) {
									taken = 1;
									break;
								}
								alone = 0;
							}
						}

						if (!taken && c->inbuf[0] != '\0') {

							if(sscanf(c->inbuf, " %23[^\n]", c->nickname) != 1) {
								// Failed to read username
								queue_message(c, "Invalid username, try again:");
								continue; // Ask again
							}
							//snprintf(c->inbuf, MAX_USERNAME_LEN, "%s", c->nickname);

							c->nickname[MAX_USERNAME_LEN-1] = '\0';

							// Send welcome message
							char welcome[MAX];
							if (alone) snprintf(welcome, MAX, "<Server→You> Welcome, %s! You are the first user here.", c->nickname);
							else snprintf(welcome, MAX, "<Server→You> Welcome, %s! There are other users here.", c->nickname);
							
							queue_message(c, welcome);
							//queue_message(c, "You can now start sending messages.\n");
							//queue_message(c, "-------------------------------------------------\n");
							//queue_message(c, "To change your nickname, disconnect and reconnect\n");
							//queue_message(c, "NOT SURE WHAT'S GOING ON HERE? CHECK OUT THE README FILE..............\n");

							char message[MAX];
							snprintf(message, MAX, "<Server> %s has joined the chat.", c->nickname);
							broadcast_message(&clients, clisockfd, message);
							continue; // Done processing this client
						} else {
							// Username taken or invalid
							queue_message(c, "Username unavailable or invalid, try again:\0");
							continue; // Ask again
						}

					} else { // NORMAL MESSAGE PROCESSING

						if (c->inbuf[0] == '\0') continue; // empty message, ignore

						char message[MAX + MAX_USERNAME_LEN + 4];
						snprintf(message, sizeof(message), "[%s] %s", c->nickname, c->inbuf);

						// if message is too long, broadcast_message will truncate it
						// to MAX length, which is fine
						broadcast_message(&clients, clisockfd, message);
						
						// this is to queue the message back to the sender as well
						// only use if you are overwriting the message in the client window
							// snprintf(message, sizeof(message), "[You] %s", c->inbuf);	
							//queue_message(c, message);
					}
				}
			} /* FD_ISSET read */

			/* WRITABLE? */
			if (FD_ISSET(clisockfd, &writeset)) {
				struct outmsg *m = TAILQ_FIRST(&c->msgq);
				if (!m) continue;   // no messages queued

				size_t remaining = m->len - m->sent;

				//TODO: Does this need to get changed the same way nread was changed?
				//ssize_t nwrite = write(clisockfd, m->data + m->sent, remaining); // can probably write as MAX FIXME
				//CHECK(gnutls_record_send(c->session, m->data + m->sent, ret));

				ret = gnutls_record_send(c->session,
					m->data + m->sent,
					remaining);

				printf("Wrote %d bytes to client %d\n", ret, clisockfd);

				if (ret > 0) {
					m->sent += ret;
					if (m->sent == m->len) {
						TAILQ_REMOVE(&c->msgq, m, entries); // sends only one message from queue per iteration, should be fine (Euguene said)
						free(m->data);
						free(m);
					}
				} else if (ret < 0) {
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						// try later 
					} else {
						fprintf(stderr, "Error writing to client %d: %s\n", clisockfd, strerror(errno));
						remove_client(&clients, c);
						continue;
					}
				} 
            } /*    FD_ISSET write */
		} /*     LIST_FOREACH_SAFE */
	} /*                  for (;;) */
}

static int connect_to_directory(const char *server_name, int port, gnutls_session_t dir_session, gnutls_certificate_credentials_t x509_cred) {
    int sockfd;
    struct sockaddr_in dir_addr;
    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = htonl(INADDR_ANY);
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

	gnutls_init(&dir_session, GNUTLS_CLIENT);
	gnutls_credentials_set(dir_session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_handshake_set_timeout(dir_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	gnutls_priority_set_direct(dir_session, "NORMAL", NULL);
	gnutls_transport_set_int(dir_session, sockfd);
	int ret = 0;
	LOOP_CHECK(ret, gnutls_handshake(dir_session));
	if (ret < 0) {
		close(sockfd);
		gnutls_deinit(dir_session);
		fprintf(stderr, "*** Handshake has failed (%s)\n\n",
			gnutls_strerror(ret));
		return EXIT_FAILURE;
	}
	printf("- Handshake was completed\n");

    // Send handshake: "SERVER <port> <server_name>"
    char handshake[MAX] = {0};
    snprintf(handshake, sizeof(handshake), "SERVER %d %s\n", port, server_name);
	printf("Sending handshake to directory server.\n\tHandshake: %s", handshake);
	CHECK(ret = gnutls_record_send(dir_session, handshake, MAX));
    if (ret < 0) {
        perror("handshake failed");
        close(sockfd);
        return -1;
    }

    return sockfd; // idle connection
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

static void broadcast_message(struct clientlist *clients, int sender_sockfd, const char *message) {
    struct client *c, *tmp;
    LIST_FOREACH_SAFE(c, clients, client_entries, tmp) {
		// fprintf(stderr, "Broadcasting message to client %d from sender client %d\n", c->sockfd, sender_sockfd);
        if (c->sockfd != sender_sockfd) { // Don't send the message back to the sender
            queue_message(c, message);
        }
    }
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
