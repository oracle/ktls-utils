/*
 * Record audit and debugging information in the system log.
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

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include "tlshd.h"

int tlshd_debug;
int tlshd_library_debug;

/**
 * tlshd_log_success - Emit "handshake successful" notification
 * @hostname: peer's DNS name
 * @sap: peer's IP address
 * @salen: length of IP address
 *
 */
void tlshd_log_success(const char *hostname, const struct sockaddr *sap,
		       socklen_t salen)
{
	char buf[NI_MAXHOST];

	getnameinfo(sap, salen, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
	syslog(LOG_INFO, "Handshake with %s (%s) was successful\n",
		hostname, buf);
}

/**
 * tlshd_log_failure - Emit "handshake failed" notification
 * @hostname: peer's DNS name
 * @sap: peer's IP address
 * @salen: length of IP address
 *
 */
void tlshd_log_failure(const char *hostname, const struct sockaddr *sap,
		       socklen_t salen)
{
	char buf[NI_MAXHOST];

	getnameinfo(sap, salen, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
	syslog(LOG_ERR, "Handshake with %s (%s) failed\n",
		hostname, buf);
}

/**
 * tlshd_log_debug - Emit a debugging notification
 * @fmt - printf-style format string
 *
 */
void tlshd_log_debug(const char *fmt, ...)
{
	va_list args;

	if (!tlshd_debug)
		return;

	va_start(args, fmt);
	vsyslog(LOG_DEBUG, fmt, args);
	va_end(args);
}

/**
 * tlshd_log_error - Emit a generic error notification
 * @msg: message to log
 *
 */
void tlshd_log_error(const char *msg)
{
	syslog(LOG_ERR, "%s\n", msg);
}

/**
 * tlshd_log_perror - Emit "system call failed" notification
 * @sap: remote address to log
 *
 */
void tlshd_log_perror(const char *prefix)
{
	syslog(LOG_NOTICE, "%s: %s\n", prefix, strerror(errno));
}

/**
 * tlshd_log_gai_error - Emit "getaddr/nameinfo failed" notification
 * @error: error code returned by getaddrinfo(3) or getnameinfo(3)
 *
 */
void tlshd_log_gai_error(int error)
{
	syslog(LOG_NOTICE, "%s\n", gai_strerror(error));
}

/**
 * tlshd_log_gnutls_error - Emit "library call failed" notification
 * @error: GnuTLS error code to log
 *
 */
void tlshd_log_gnutls_error(int error)
{
	syslog(LOG_NOTICE, "gnutls: %s (%d)\n", gnutls_strerror(error), error);
}

/**
 * tlshd_gnutls_log_func - Library callback function to log a message
 * @level: log level
 * @msg: message to log
 *
 */
void tlshd_gnutls_log_func(int level, const char *msg)
{
	syslog(LOG_DEBUG, "gnutls(%d): %s", level, msg);
}

/**
 * tlshd_gnutls_audit_func - Library callback function to log an audit message
 * @session: controlling GnuTLS session
 * @msg: message to log
 *
 */
void tlshd_gnutls_audit_func(__attribute__ ((unused)) gnutls_session_t session,
			     const char *msg)
{
	syslog(LOG_INFO, "audit: %s", msg);
}

/**
 * tlshd_log_init - Initialize audit logging
 * @progname: NUL-terminated string containing program name
 *
 */
void tlshd_log_init(const char *progname)
{
	int option;

	option = LOG_NDELAY;
	if (tlshd_debug)
		option |= LOG_PERROR;
	openlog(progname, option, LOG_AUTH);

	syslog(LOG_NOTICE, "Built from " PACKAGE_STRING " on " __DATE__ " " __TIME__);
}

/**
 * tlshd_log_shutdown - Log a tlshd shutdown notice
 *
 */
void tlshd_log_shutdown(void)
{
	syslog(LOG_NOTICE, "Shutting down.");
}

/**
 * tlshd_log_close - Release audit logging resources
 *
 */
void tlshd_log_close(void)
{
	closelog();
}
