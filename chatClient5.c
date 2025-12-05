#define _GNU_SOURCE
#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#define CAFILE "certs/rootCA.crt"

/* Code from GnuTLS documentation */

//#define CHECK(x) assert((x) >= 0) DONT USE CHECK BECAUSE WE NEED TO GET RETURN VALUES
#define LOOP_CHECK(rval, cmd) \
	do {                  \
		rval = cmd;   \
	} while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

/* End code from GnuTLS documentation */

int connect_to_server(const char *ip, int port, gnutls_session_t *session, gnutls_certificate_credentials_t x509_cred, char* topic) {
    printf("Connecting to a server\n");
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

    gnutls_init(session, GNUTLS_CLIENT);
    gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	gnutls_handshake_set_timeout(*session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	gnutls_priority_set_direct(*session, "NORMAL", NULL);
    gnutls_session_set_verify_cert(*session, topic, 0);

	gnutls_transport_set_int(*session, sockfd);
	int ret = 0;
	LOOP_CHECK(ret, gnutls_handshake(*session));
	if (ret < 0) {
		close(sockfd);
		gnutls_deinit(*session);
		fprintf(stderr, "*** Handshake has failed (%s)\n\n",
			gnutls_strerror(ret));
		return -1;
	}

	printf("- Handshake was completed\n");

    //Parse directory server connection
    // char dn[256];
    // ssize_t size = sizeof(dn);
    // gnutls_x509_crt_get_dn(cert, dn, &size);
    // printf("\tDN: %s\n", dn);

    return sockfd;
}

int main()
{
	char buf[MAX] = {'\0'};

    int dir_sock;

    gnutls_session_t dir_session;
    gnutls_certificate_credentials_t x509_cred;

    gnutls_global_init();
	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	//gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM); //We don't have credentials as the client (in this case)

    /* --- Connect to directory server --- */
    dir_sock = connect_to_server(SERV_HOST_ADDR, SERV_TCP_PORT, &dir_session, x509_cred, "Directory Server");
    if (dir_sock < 0) return EXIT_FAILURE;

    fprintf(stderr, "Connected to directory server at %s:%d\n", SERV_HOST_ADDR, SERV_TCP_PORT);
	
    /* --- Send initial CLIENT handshake --- */
    char handshake[MAX] = {'\0'}; 
    snprintf(handshake, MAX-10, "CLIENT\n");
    if (gnutls_record_send(dir_session, handshake, MAX) < 0) {
        perror("Error sending CLIENT handshake");
        close(dir_sock);
        return EXIT_FAILURE;
    }
    printf("Sent CLIENT handshake to directory server\n\n");

    fd_set readset;
    int sockfd = -1;
    char server_ip[INET_ADDRSTRLEN];
    int server_port;
    gnutls_session_t server_session;


	while (1) {
        /* Wait for response from directory server */
        FD_ZERO(&readset);
        FD_SET(STDIN_FILENO, &readset);
        FD_SET(dir_sock, &readset);

        int n = select(dir_sock + 1, &readset, NULL, NULL, NULL);
        if (n <= 0) {
            fprintf(stderr, "Select error\n");
            close(dir_sock);
            return EXIT_FAILURE;
        }

        if (FD_ISSET(STDIN_FILENO, &readset)) {
                            /* Read user input */
                if (fgets(buf, MAX, stdin)) {
                    
                    if (strnlen(buf, MAX) > 0 && buf[strnlen(buf, MAX) - 1] == '\n') {
                        buf[strnlen(buf, MAX) - 1] = '\0'; // Remove newline
                    }

                    //write(dir_sock, buf, MAX);

                    int ret = gnutls_record_send(dir_session, buf, MAX);
                    if (ret < 0) {
                        if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
                            fprintf(stderr, "TLS send would block, try again\n");
                        } else {
                            fprintf(stderr, "TLS send failed: %s\n", gnutls_strerror(ret));
                            close(sockfd);
                            return EXIT_FAILURE;
                        }
                    } else {
                        //fprintf(stderr, "DEBUG: Sent %d bytes over TLS\n", ret);
                    }


                } else {
					fprintf(stderr, "Error reading user input\n");
					close(dir_sock);
					return EXIT_FAILURE;
				}
                fprintf(stderr, "> "); // Prompt for input
                fflush(stderr);

        }

        if (FD_ISSET(dir_sock, &readset)) {
            //ssize_t nread = read(dir_sock, buf, MAX - 1);
                /*    if (nread <= 0) {
                    fprintf(stderr, "Directory server closed connection\n");
                    close(dir_sock);
                    return EXIT_FAILURE;
                }
                buf[nread] = '\0'; */


            int ret = gnutls_record_recv(dir_session, buf, MAX);
            //printf("Read returned %d: %s\n", ret, buf);
            if (ret == 0) {
                fprintf(stderr, "TLS connection closed by directory server\n");
                gnutls_bye(dir_session, GNUTLS_SHUT_RDWR); 
                fprintf(stderr, "%s:%d Error reading from directory server\n", __FILE__, __LINE__); //DEBUG
                close(sockfd);
                return EXIT_FAILURE;
            }
            else if (ret < 0) {
                if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
                    // Non-fatal, try again later
                    fprintf(stderr, "TLS recv would block, retrying\n");
                    continue;
                } else {
                    fprintf(stderr, "TLS recv failed: %s\n", gnutls_strerror(ret));
                    close(sockfd);
                    return EXIT_FAILURE;
                }
            }
            //else {
            if (ret < MAX) buf[ret] = '\0';  // null-terminate the string
            else buf[MAX - 1] = '\0'; // ensure null-termination

                //fprintf(stderr, "\r\033[K");
                //fprintf(stderr, "%s\n", buf);

                //fprintf(stderr, "> ");
                //fflush(stderr);

                //fprintf(stderr, "DEBUG: Received %d bytes over TLS\n", ret);

            /* Check if server accepted client */
            //printf("Read buffer: %s\n", buf);
            if (strncmp(buf, "SERVER_INFO ", 12) == 0) {
                printf("Directory server provided server info: %s\n", buf);
                /* Parse IP and PORT */
                char server_topic[MAX];
                if (sscanf(buf + 12, "%63s %d %[^\n\t]", server_ip, &server_port, server_topic) != 3) {
                    fprintf(stderr, "Malformed SERVER_INFO: %s\n", buf);
                    close(dir_sock);
                    return EXIT_FAILURE;
                }

                /* Connect to selected server */
                sockfd = connect_to_server(server_ip, server_port, &server_session, x509_cred, server_topic);
                if (sockfd < 0) {
                    fprintf(stderr, "Failed to connect to server %s:%d\n", server_ip, server_port);
                    close(dir_sock);
                    return EXIT_FAILURE;
                }

                fprintf(stderr, "Connected to server %s:%d\n", server_ip, server_port);
                break; // Proceed to username input
            } else {
                /* Directory server sent a list or rejection, display to user */
                
                fprintf(stderr, "\r\033[K");
                fprintf(stderr, "%s\n", buf);

				if (strncmp(buf, "No servers available.", 21) == 0) {
					fprintf(stderr, "Exiting due to no available servers.\n");
					close(dir_sock);
					return EXIT_FAILURE;
				}

                if (strncmp(buf, "Maximum clients reached. Try again later.", 41) == 0) {
                    fprintf(stderr, "Exiting due to maximum clients reached on directory server.\n");
                    close(dir_sock);
                    return EXIT_FAILURE;
                }

                //fprintf(stderr, "%s\n", buf);

                //fprintf(stderr, "> ");
                //fflush(stderr);


                fprintf(stderr, "Select a server number: ");
                fflush(stderr);

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

		int n;
		if ((n=select(sockfd+1, &readset, NULL, NULL, NULL)) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				/* Read a line from stdin */
				if (fgets(buf, MAX, stdin)) {

					// Trim newline if present
				    /* char fmt[20];
					    snprintf(fmt, sizeof(fmt), "%%%d[^\n]", MAX - 1);
                        #pragma GCC diagnostic push
                        #pragma GCC diagnostic ignored "-Wformat-nonliteral"
                        sscanf(buf, fmt, buf);
                        #pragma GCC diagnostic pop
                    */

                    //fprintf(buf, "%99[^\n]", buf);

                    if(sscanf(buf, " %1000[^\n]", buf) != 1) // Remove newline character
					{
						fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
						fprintf(stderr, "> "); // Prompt for input
						fflush(stderr);
 
						continue;
					}


					/* Send the user's message to the server */
					//write(sockfd, buf, MAX);

                    int ret = gnutls_record_send(server_session, buf, MAX);
                    if (ret < 0) {
                        if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
                            fprintf(stderr, "TLS send would block, try again\n");
                        } else {
                            fprintf(stderr, "TLS send failed: %s\n", gnutls_strerror(ret));
                            close(sockfd);
                            return EXIT_FAILURE;
                        }
                    } else {
                        //fprintf(stderr, "DEBUG: Sent %d bytes over TLS\n", ret);
                    }

				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
				}
				fprintf(stderr, "> "); // Prompt for input
				fflush(stderr);
                fflush(stdin);
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
                int ret = gnutls_record_recv(server_session, buf, MAX);

                if (ret == 0) {
                    fprintf(stderr, "TLS connection closed by server\n");
                    //gnutls _bye(server_session, GNUTLS_SHUT_RDWR);
                    fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__); //DEBUG

                    close(sockfd);
                    return EXIT_FAILURE;
                }
                else if (ret < 0) {
                    if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
                        // Non-fatal, try again later
                        fprintf(stderr, "TLS recv would block, retrying\n");
                        continue;
                    } else {
                        fprintf(stderr, "TLS recv failed: %s\n", gnutls_strerror(ret));
                        close(sockfd);
                        return EXIT_FAILURE;
                    }
                }
                else {
					if (ret < MAX) buf[ret] = '\0';  // null-terminate the string
					else buf[MAX - 1] = '\0'; // ensure null-termination

                    fprintf(stderr, "\r\033[K");
                    fprintf(stderr, "%s\n", buf);

                    fprintf(stderr, "> ");
                    fflush(stderr);

                    //fprintf(stderr, "DEBUG: Received %d bytes over TLS\n", ret);
                }

                /* ssize_t nread = read(sockfd, buf, MAX);
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
				 } */



			}
		}
	}
	close(sockfd);
	close(dir_sock);
	// return or exit(0) is implied; no need to do anything because main() ends
}
