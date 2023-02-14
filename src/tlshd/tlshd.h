/*
 * Generic definitions and forward declarations for tlshd.
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

#include <linux/netlink.h>

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))

extern int tlshd_debug;
extern int tlshd_library_debug;
extern int tlshd_stderr;
extern GKeyFile *tlshd_configuration;
extern int tlshd_completion_status;
extern long tlshd_keyring;

struct tlshd_handshake_parms {
	char		*peername;
	int		sockfd;
	int		protocol;
	int		handshake_type;
	int		timeout;
	int		auth_type;
	char		*priorities;
	key_serial_t	x509_cert;
	key_serial_t	x509_privkey;
	key_serial_t	peerid;
	int		status;
};

/* config.c */
bool tlshd_config_init(const gchar *pathname);
void tlshd_config_shutdown(void);
bool tlshd_config_get_client_cert(gnutls_pcert_st *cert);
bool tlshd_config_get_client_privkey(gnutls_privkey_t *privkey);
bool tlshd_config_get_server_cert(gnutls_pcert_st *cert);
bool tlshd_config_get_server_privkey(gnutls_privkey_t *privkey);

/* handshake.c */
extern void tlshd_service_socket(void);

/* keyring.c */
extern bool tlshd_keyring_get_psk_username(key_serial_t serial,
					   char **username);
extern bool tlshd_keyring_get_psk_key(key_serial_t serial,
				      gnutls_datum_t *key);
extern bool tlshd_keyring_get_privkey(key_serial_t serial,
				      gnutls_privkey_t privkey);
extern bool tlshd_keyring_get_cert(key_serial_t serial, gnutls_pcert_st *cert);
extern int tlshd_link_keyring(const char *keyring);
extern void tlshd_unlink_keyring(void);

/* ktls.c */
extern int tlshd_initialize_ktls(gnutls_session_t session);

/* log.c */
extern void tlshd_log_init(const char *progname);
extern void tlshd_log_shutdown(void);
extern void tlshd_log_close(void);

extern void tlshd_log_success(const char *hostname,
			      const struct sockaddr *sap, socklen_t salen);
extern void tlshd_log_failure(const char *hostname,
			      const struct sockaddr *sap, socklen_t salen);

void tlshd_log_debug(const char *fmt, ...);
extern void tlshd_log_error(const char *msg);
extern void tlshd_log_perror(const char *prefix);
extern void tlshd_log_gai_error(int error);

extern void tlshd_log_cert_verification_error(gnutls_session_t session);
extern void tlshd_log_gnutls_error(int error);
extern void tlshd_gnutls_log_func(int level, const char *msg);
extern void tlshd_gnutls_audit_func(gnutls_session_t session, const char *msg);

void tlshd_log_gerror(const char *msg, GError *error);
void tlshd_log_nl_error(const char *msg, int err);

/* netlink.c */
extern int tlshd_nl_get_handshake_parms(struct tlshd_handshake_parms *parms);
extern void tlshd_nl_done(struct tlshd_handshake_parms *parms);

/* tls13.c */
extern void tlshd_tls13_handler(struct tlshd_handshake_parms *parms);

#if !defined(TLS_DEFAULT_PRIORITIES)

/*
 * New HANDSHAKE netlink options that will eventually appear in
 * uapi/linux/handshake.h.
 */

#define NETLINK_HANDSHAKE	23
#define TLS_DEFAULT_PRIORITIES	(NULL)

/* Multicast Netlink socket groups */
enum handshake_nlgrps {
	HANDSHAKE_NLGRP_NONE = 0,
	HANDSHAKE_NLGRP_TLS_13,
	__HANDSHAKE_NLGRP_MAX
};
#define HSNLGRP_MAX	(__HANDSHAKE_NLGRP_MAX - 1)

enum handshake_nl_msgs {
	HANDSHAKE_NL_MSG_BASE = NLMSG_MIN_TYPE,
	HANDSHAKE_NL_MSG_READY,
	HANDSHAKE_NL_MSG_ACCEPT,
	HANDSHAKE_NL_MSG_DONE,
	__HANDSHAKE_NL_MSG_MAX
};
#define HANDSHAKE_NL_MSG_MAX	(__HANDSHAKE_NL_MSG_MAX - 1)

enum handshake_nl_attrs {
	HANDSHAKE_NL_ATTR_UNSPEC = 0,
	HANDSHAKE_NL_ATTR_MSG_STATUS,
	HANDSHAKE_NL_ATTR_SOCKFD,
	HANDSHAKE_NL_ATTR_PROTOCOL,
	HANDSHAKE_NL_ATTR_ACCEPT_RESP,
	HANDSHAKE_NL_ATTR_DONE_ARGS,

	HANDSHAKE_NL_ATTR_TLS_TYPE = 20,
	HANDSHAKE_NL_ATTR_TLS_AUTH,
	HANDSHAKE_NL_ATTR_TLS_PRIORITIES,
	HANDSHAKE_NL_ATTR_TLS_X509_CERT,
	HANDSHAKE_NL_ATTR_TLS_X509_PRIVKEY,
	HANDSHAKE_NL_ATTR_TLS_PSK,
	HANDSHAKE_NL_ATTR_TLS_SESS_STATUS,
	HANDSHAKE_NL_ATTR_TLS_PEERID,
	HANDSHAKE_NL_ATTR_TLS_TIMEOUT,

	__HANDSHAKE_NL_ATTR_MAX
};
#define HANDSHAKE_NL_ATTR_MAX	(__HANDSHAKE_NL_ATTR_MAX - 1)

enum handshake_nl_status {
	HANDSHAKE_NL_STATUS_OK = 0,
	HANDSHAKE_NL_STATUS_INVAL,
	HANDSHAKE_NL_STATUS_BADF,
	HANDSHAKE_NL_STATUS_NOTREADY,
	HANDSHAKE_NL_STATUS_SYSTEMFAULT,
};

enum handshake_nl_protocol {
	HANDSHAKE_NL_PROTO_UNSPEC = 0,
	HANDSHAKE_NL_PROTO_TLS_13,
};

enum handshake_nl_tls_type {
	HANDSHAKE_NL_TLS_TYPE_UNSPEC = 0,
	HANDSHAKE_NL_TLS_TYPE_CLIENTHELLO,
	HANDSHAKE_NL_TLS_TYPE_SERVERHELLO,
};

enum handshake_nl_tls_auth {
	HANDSHAKE_NL_TLS_AUTH_UNSPEC = 0,
	HANDSHAKE_NL_TLS_AUTH_UNAUTH,
	HANDSHAKE_NL_TLS_AUTH_X509,
	HANDSHAKE_NL_TLS_AUTH_PSK,
};

enum {
	HANDSHAKE_NO_PEERID = 0,
	HANDSHAKE_NO_CERT = 0,
	HANDSHAKE_NO_PRIVKEY = 0,
};

enum handshake_nl_tls_session_status {
	HANDSHAKE_NL_TLS_SESS_STATUS_OK = 0,	/* session established */
	HANDSHAKE_NL_TLS_SESS_STATUS_FAULT,	/* failure to launch */
	HANDSHAKE_NL_TLS_SESS_STATUS_REJECTED,	/* remote hates us */
};

#endif /* !defined(TLS_DEFAULT_PRIORITIES) */
