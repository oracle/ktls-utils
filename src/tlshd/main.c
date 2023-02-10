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

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>


#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>

#include "tlshd.h"

static const char *optstring = "c:h:sv";
static const struct option longopts[] = {
	{ "config",	required_argument,	NULL,	'c' },
	{ "help",	no_argument,		NULL,	'h' },
	{ "stderr",	no_argument,		NULL,	's' },
	{ "version",	no_argument,		NULL,	'v' },
	{ NULL,		0,			NULL,	 0 }
};

static void tlshd_wait_for_events(void)
{
	struct nl_sock *nls;
	int err;

	nls = nl_socket_alloc();
	if (!nls) {
		tlshd_log_debug("%s: Failed to allocate netlink socket.", __func__);
		return;
	}

	err = nl_connect(nls, NETLINK_HANDSHAKE);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_connect", err);
		goto out_free;
	}

	nl_socket_disable_seq_check(nls);
	err = nl_socket_add_membership(nls, HANDSHAKE_NLGRP_TLS_13);
	if (err < 0) {
		tlshd_log_nl_error("nl_socket_add_membership", err);
		goto out_close;
	}

	while (true) {
		err = nl_recvmsgs_default(nls);
		if (err < 0) {
			tlshd_log_nl_error("nl_recvmsgs", err);
			break;
		}

		tlshd_log_debug("%s: Event received... (%d)\n", __func__, err);
		if (!fork()) {
			tlshd_service_socket();
			tlshd_log_debug("%s: Child exiting...\n", __func__);
			tlshd_log_close();
			exit(EXIT_SUCCESS);
		}
	};
	tlshd_log_debug("%s: exiting event loop...\n", __func__);

	nl_socket_drop_membership(nls, HANDSHAKE_NLGRP_TLS_13);
out_close:
	nl_close(nls);
out_free:
	nl_socket_free(nls);
}

int main(int argc, char **argv)
{
	static gchar config_file[PATH_MAX + 1] = "/etc/tlshd.conf";
	char *progname;
	int c;
	size_t len;

	tlshd_library_debug = 0;
	progname = basename(argv[0]);
	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
		switch (c) {
		case 'c':
			len = sizeof(config_file) - 1;
			if (strlen(optarg) >= len) {
				fprintf(stderr, "Invalid config file\n");
				return EXIT_FAILURE;
			}
			strncpy(config_file, optarg, len);
			config_file[len] = '\0';
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
			fprintf(stderr, "usage: %s [-chsv]\n", progname);
		}
	}

	tlshd_log_init(progname);

	if (!tlshd_config_init(config_file)) {
		tlshd_log_shutdown();
		tlshd_log_close();
		return EXIT_FAILURE;
	}

	tlshd_wait_for_events();

	tlshd_config_shutdown();
	tlshd_log_shutdown();
	tlshd_log_close();
	return EXIT_SUCCESS;
}
