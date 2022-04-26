/*
 * Handle a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 *
 * Copyright (c) 2022 Oracle and/or its affiliates.
 *
 * ktls-utils is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <libgen.h>
#include <keyutils.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include "tlshd.h"

#define TLSH_LISTENER_BACKLOG	(20)

static const char *optstring = "dhl:nv";
static const struct option longopts[] = {
	{ "debug",	no_argument,		NULL,	'd' },
	{ "help",	no_argument,		NULL,	'h' },
	{ "libdebug",	required_argument,	NULL,	'l' },
	{ "noverify",	no_argument,		NULL,	'n' },
	{ "stderr",	no_argument,		NULL,	's' },
	{ "version",	no_argument,		NULL,	'v' },
	{ NULL,		0,			NULL,	 0 }
};

static int tlshd_make_listener(struct sockaddr *sap, socklen_t saplen)
{
	int sock;

	sock = socket(AF_TLSH, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (sock == -1) {
		tlshd_log_perror("socket");
		return -1;
	}
	if (bind(sock, sap, saplen)) {
		tlshd_log_perror("bind");
		return -1;
	}
	if (listen(sock, TLSH_LISTENER_BACKLOG)) {
		tlshd_log_perror("listen");
		return -1;
	}

	return sock;
}

static void tlshd_parse_poll_result(struct pollfd *fds, nfds_t nfds)
{
	pid_t pid;
	nfds_t i;
	int fd;

	signal(SIGCHLD, SIG_IGN);
	for (i = 0; i < nfds; i++) {
		if (!(fds[i].revents & POLLIN))
			continue;

		fd = accept(fds[i].fd, NULL, NULL);
		if (fd == -1) {
			/*
			 * Linux accept(2) passes already-pending network
			 * errors on the new socket as an error code from
			 * accept(2).
			 */
			tlshd_log_perror("accept");
			continue;
		}

		pid = fork();
		if (!pid) {
			tlshd_service_socket(fd);
			tlshd_log_close();
			exit(EXIT_SUCCESS);
		}

		close(fd);
	}
}

static void tlshd_poll(void)
{
	union {
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
		struct sockaddr		sa;
	} u;
	struct pollfd fds[2];

	u.sin.sin_family = AF_INET;
	u.sin.sin_addr.s_addr = INADDR_ANY;
	fds[0].fd = tlshd_make_listener(&u.sa, sizeof(u.sin));
	if (fds[0].fd == -1)
		return;

	u.sin6.sin6_family = AF_INET6;
	u.sin6.sin6_addr = in6addr_any;
	fds[1].fd = tlshd_make_listener(&u.sa, sizeof(u.sin6));
	if (fds[0].fd == -1)
		goto out_close0;

	while (1) {
		unsigned long i;

		for (i = 0; i < ARRAY_SIZE(fds); i++) {
			fds[i].events = POLLIN;
			fds[i].revents = 0;
		}
		if (poll(fds, ARRAY_SIZE(fds), -1) == -1) {
			tlshd_log_perror("poll");
			break;
		}
		tlshd_parse_poll_result(fds, ARRAY_SIZE(fds));
	}

	close(fds[1].fd);
out_close0:
	close(fds[0].fd);
}

int main(int argc, char **argv)
{
	char *progname;
	int c;

	tlshd_debug = 0;
	tlshd_library_debug = 0;
	progname = basename(argv[0]);
	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
		switch (c) {
		case 'd':
			/* Eventually this option will set a debug level */
			tlshd_debug = 1;
			break;
		case 'l':
			tlshd_library_debug = atoi(optarg);
			break;
		case 'n':
			tlshd_verify_server = 0;
			break;
		case 's':
			tlshd_stderr = 1;
			break;
		case 'v':
			fprintf(stderr, "%s, built from " PACKAGE_STRING
				" on " __DATE__ " " __TIME__ "\n",
				progname);
			return EXIT_SUCCESS;
		case 'h':
		default:
			fprintf(stderr, "usage: %s [-dT]\n", progname);
		}
	}

	tlshd_log_init(progname);

	tlshd_poll();

	tlshd_log_shutdown();
	tlshd_log_close();
	return EXIT_SUCCESS;
}
