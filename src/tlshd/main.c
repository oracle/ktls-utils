/**
 * @file main.c
 * @brief Handle a request for a TLS handshake on behalf of an
 *	  in-kernel TLS consumer
 *
 * @copyright
 * Copyright (c) 2022 - 2023 Oracle and/or its affiliates.
 */

/*
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

#include <config.h>

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

/**
 * @page tlshd TLS handshake daemon
 *
 * The tlshd daemon is a user agent that services TLS handshake
 * requests on behalf of kernel TLS consumers. It materializes kernel
 * socket endpoints in user space in order to perform TLS handshakes
 * using a standard TLS library. After each handshake completes, tlshd
 * plants the TLS session key into the socket to enable the use of
 * kTLS to secure subsequent communication on that socket. The socket
 * is then passed back to the kernel.
 *
 * @section man8 Man pages
 * @subsection tlshd_8 tlshd.8
 * @htmlinclude tlshd.8.html
 */

static const char *optstring = "c:hsv";
static const struct option longopts[] = {
	{ "config",	required_argument,	NULL,	'c' },
	{ "help",	no_argument,		NULL,	'h' },
	{ "stderr",	no_argument,		NULL,	's' },
	{ "version",	no_argument,		NULL,	'v' },
	{ NULL,		0,			NULL,	 0 }
};

/**
 * @brief Emit a program usage message on stderr
 * @param[in]     progname  NUL-terminated C string containing program name
 */
static void usage(char *progname)
{
	fprintf(stderr, "usage: %s [-chsv]\n", progname);
}

/**
 * @brief tlshd program entry point
 * @param[in]     argc  Count of elements in "argv"
 * @param[in]     argv  Command line parameters
 *
 * @retval EXIT_SUCCESS  Program terminated normally
 * @retval EXIT_FAILURE  Program encountered an error
 */
int main(int argc, char **argv)
{
	static gchar config_file[PATH_MAX + 1];
	char *progname;
	int c;
	size_t len;

	tlshd_tls_debug = 0;
	progname = basename(argv[0]);
	config_file[0] = '\0';
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

	if (config_file[0] != '\0') {
		if (!tlshd_config_init(config_file, false)) {
			tlshd_log_shutdown();
			tlshd_log_close();
			return EXIT_FAILURE;
		}
	} else {
		if (tlshd_config_init("/etc/tlshd.conf", true)) {
			tlshd_log_notice("Please relocate /etc/tlshd.conf to /etc/tlshd/config");
		} else if (!tlshd_config_init("/etc/tlshd/config", false)) {
			tlshd_log_shutdown();
			tlshd_log_close();
			return EXIT_FAILURE;
		}
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
