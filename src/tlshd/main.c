/*
 * Handle a request for a TLS handshake on behalf of an
 * in-kernel TLS consumer.
 *
 * Copyright (c) 2022 - 2023 Oracle and/or its affiliates.
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

static const char *optstring = "c:hsv";
static const struct option longopts[] = {
	{ "config",	required_argument,	NULL,	'c' },
	{ "help",	no_argument,		NULL,	'h' },
	{ "stderr",	no_argument,		NULL,	's' },
	{ "version",	no_argument,		NULL,	'v' },
	{ NULL,		0,			NULL,	 0 }
};

void usage(char *progname) {
		fprintf(stderr, "usage: %s [-chsv]\n", progname);
}

int main(int argc, char **argv)
{
	static gchar config_file[PATH_MAX + 1] = "/etc/tlshd.conf";
	char *progname;
	int c;
	size_t len;

	tlshd_tls_debug = 0;
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
			usage(progname);
			return EXIT_SUCCESS;
		default:
			usage(progname);
			return EXIT_FAILURE;
		}
	}

	tlshd_log_init(progname);

	if (!tlshd_config_init(config_file)) {
		tlshd_log_shutdown();
		tlshd_log_close();
		return EXIT_FAILURE;
	}

	if (tlshd_gnutls_priority_init()) {
		tlshd_config_shutdown();
		tlshd_log_shutdown();
		tlshd_log_close();
		return EXIT_FAILURE;
	}

	tlshd_genl_dispatch();

	tlshd_gnutls_priority_deinit();
	tlshd_config_shutdown();
	tlshd_log_shutdown();
	tlshd_log_close();
	return EXIT_SUCCESS;
}
