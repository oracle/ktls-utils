/**
 * @file log.c
 * @brief Record audit and debugging information in the system log
 *
 * @copyright
 * Copyright (c) 2022 Oracle and/or its affiliates.
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

#include <netlink/errno.h>

#include <glib.h>

#include "tlshd.h"

/**
 * @var int tlshd_debug
 * Global debug verbosity setting
 */
int tlshd_debug;

/**
 * @var int tlshd_tls_debug
 * Global debug verbosity setting for TLS library calls
 */
int tlshd_tls_debug;

/**
 * @var int tlshd_stderr
 * Global setting to output on stderr as well as syslog
 */
int tlshd_stderr;

/**
 * @brief Emit completion notification
 * @param[in]     parms  Handshake parameters
 */
void tlshd_log_completion(struct tlshd_handshake_parms *parms)
{
	const char *status = "succeeded";
	int priority = LOG_INFO;

	if (!tlshd_debug)
		return;

	if (parms->session_status) {
		status = "failed";
		priority = LOG_ERR;
	}
	if (parms->peername && parms->peeraddr)
		syslog(priority, "Handshake with '%s' (%s) %s\n",
		       parms->peername, parms->peeraddr, status);
	else
		syslog(priority, "Handshake request %s\n", status);
}

/**
 * @brief Emit a debugging notification
 * @param[in]     fmt  printf-style format string
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
 * @brief Emit a generic error notification
 * @param[in]     fmt  printf-style format string
 */
void tlshd_log_error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsyslog(LOG_ERR, fmt, args);
	va_end(args);
}

/**
 * @brief Emit a generic warning
 * @param[in]     fmt  printf-style format string
 */
void tlshd_log_notice(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsyslog(LOG_NOTICE, fmt, args);
	va_end(args);
}

/**
 * @brief Emit "system call failed" notification
 * @param[in]     prefix  Identifier string
 */
void tlshd_log_perror(const char *prefix)
{
	syslog(LOG_NOTICE, "%s: %s\n", prefix, strerror(errno));
}

/**
 * @brief Emit "getaddr/nameinfo failed" notification
 * @param[in]      error  error code returned by getaddrinfo(3) or getnameinfo(3)
 */
void tlshd_log_gai_error(int error)
{
	syslog(LOG_NOTICE, "%s\n", gai_strerror(error));
}

struct tlshd_cert_status_bit {
	unsigned int	bit;
	char		*name;
};

static const struct tlshd_cert_status_bit tlshd_cert_status_names[] = {
	/* { GNUTLS_CERT_INVALID, "invalid" }, */
	{ GNUTLS_CERT_REVOKED, "revoked" },
	{ GNUTLS_CERT_SIGNER_NOT_FOUND, "signer not found" },
	{ GNUTLS_CERT_SIGNER_NOT_CA, "signer not CA" },
	{ GNUTLS_CERT_INSECURE_ALGORITHM, "uses insecure algorithm" },
	{ GNUTLS_CERT_NOT_ACTIVATED, "not activated" },
	{ GNUTLS_CERT_EXPIRED, "expired" },
	{ GNUTLS_CERT_SIGNATURE_FAILURE, "signature failure" },
	{ GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED, "revocation data superseded" },
	{ GNUTLS_CERT_UNEXPECTED_OWNER, "owner unexpected" },
	{ GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE, "revocation data issued in the future" },
	{ GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE, "signer constraints failure" },
	{ GNUTLS_CERT_MISMATCH, "mismatch" },
	{ GNUTLS_CERT_PURPOSE_MISMATCH, "purpose mismatch" },
	{ GNUTLS_CERT_MISSING_OCSP_STATUS, "has missing OCSP status" },
	{ GNUTLS_CERT_INVALID_OCSP_STATUS, "has invalid OCSP status" },
	{ GNUTLS_CERT_UNKNOWN_CRIT_EXTENSIONS, "has unknown crit extensions" },
	{ 0, NULL }
};

/**
 * @brief Report a failed certificate verification
 * @param[in]     session  Session with a failed handshake
 */
void tlshd_log_cert_verification_error(gnutls_session_t session)
{
	unsigned int status;
	int i;

	status = gnutls_session_get_verify_cert_status(session);

	for (i = 0; tlshd_cert_status_names[i].name; i++)
		if (status & tlshd_cert_status_names[i].bit)
			syslog(LOG_ERR, "Certificate %s.\n",
			       tlshd_cert_status_names[i].name);
}

/**
 * @brief Emit "library call failed" notification
 * @param[in]     error  GnuTLS error code to log
 */
void tlshd_log_gnutls_error(int error)
{
	syslog(LOG_NOTICE, "gnutls: %s (%d)\n", gnutls_strerror(error), error);
}

/**
 * @brief Library callback function to log a message
 * @param[in]     level  Log level
 * @param[in]     msg    Message to log
 */
void tlshd_gnutls_log_func(int level, const char *msg)
{
	syslog(LOG_DEBUG, "gnutls(%d): %s", level, msg);
}

/**
 * @brief Library callback function to log an audit message
 * @param[in]     session  Controlling GnuTLS session
 * @param[in]     msg      Message to log
 */
void tlshd_gnutls_audit_func(__attribute__ ((unused)) gnutls_session_t session,
			     const char *msg)
{
	syslog(LOG_INFO, "audit: %s", msg);
}

/**
 * @brief Emit glib2 "library call failed" notification
 * @param[in]     msg    Message to log
 * @param[in]     error  Error information
 */
void tlshd_log_gerror(const char *msg, GError *error)
{
	syslog(LOG_ERR, "%s: %s", msg, error->message);
}

/**
 * @brief Log a netlink error
 * @param[in]     msg  Message to log
 * @param[in]     err  Error number
 */
void tlshd_log_nl_error(const char *msg, int err)
{
	syslog(LOG_ERR, "%s: %s", msg, nl_geterror(err));
}

/**
 * @brief Initialize audit logging
 * @param[in]     progname  NUL-terminated string containing program name
 *
 */
void tlshd_log_init(const char *progname)
{
	int option;

	option = LOG_NDELAY | LOG_PID;
	if (tlshd_stderr)
		option |= LOG_PERROR;
	openlog(progname, option, LOG_AUTH);

	syslog(LOG_NOTICE, "Built from " PACKAGE_STRING " on " __DATE__ " " __TIME__);
}

/**
 * @brief Log a tlshd shutdown notice
 */
void tlshd_log_shutdown(void)
{
	syslog(LOG_NOTICE, "Shutting down.");
}

/**
 * @brief Release audit logging resources
 */
void tlshd_log_close(void)
{
	closelog();
}
