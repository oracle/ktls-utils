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
extern int tlshd_tls_debug;
extern unsigned int tlshd_delay_done;
extern int tlshd_stderr;

struct nl_sock;

struct tlshd_handshake_parms {
	char		*peername;
	struct sockaddr *peeraddr;
	socklen_t	peeraddr_len;
	int		sockfd;
	int		ip_proto;
	uint32_t	handshake_type;
	unsigned int	timeout_ms;
	uint32_t	auth_mode;
	key_serial_t	keyring;
	key_serial_t	x509_cert;
	key_serial_t	x509_privkey;
	key_serial_t	*peerids;
	unsigned int	num_peerids;
	int		msg_status;

	unsigned int	session_status;

	unsigned int	num_remote_peerids;
	key_serial_t	remote_peerid[10];
};

/* client.c */
extern void tlshd_tls13_clienthello_handshake(struct tlshd_handshake_parms *parms);
extern void tlshd_quic_clienthello_handshake(struct tlshd_handshake_parms *parms);

/* config.c */
bool tlshd_config_init(const gchar *pathname);
void tlshd_config_shutdown(void);
bool tlshd_config_get_client_truststore(char **bundle);
bool tlshd_config_get_client_certs(gnutls_pcert_st *certs,
				   unsigned int *certs_len);
bool tlshd_config_get_client_privkey(gnutls_privkey_t *privkey);
bool tlshd_config_get_server_truststore(char **bundle);
bool tlshd_config_get_server_crl(char **result);
bool tlshd_config_get_server_certs(gnutls_pcert_st *certs,
				   unsigned int *certs_len);
bool tlshd_config_get_server_privkey(gnutls_privkey_t *privkey);

/* handshake.c */
extern void tlshd_start_tls_handshake(gnutls_session_t session,
				      struct tlshd_handshake_parms *parms);
extern void tlshd_service_socket(void);

/* keyring.c */
extern bool tlshd_keyring_get_psk_username(key_serial_t serial,
					   char **username);
extern bool tlshd_keyring_get_psk_key(key_serial_t serial,
				      gnutls_datum_t *key);
extern bool tlshd_keyring_get_privkey(key_serial_t serial,
				      gnutls_privkey_t *privkey);
extern bool tlshd_keyring_get_certs(key_serial_t serial, gnutls_pcert_st *certs,
				    unsigned int *certs_len);
extern key_serial_t tlshd_keyring_create_cert(gnutls_x509_crt_t cert,
					      const char *peername);
extern int tlshd_keyring_link_session(const char *keyring);

/* ktls.c */
extern unsigned int tlshd_initialize_ktls(gnutls_session_t session);
extern int tlshd_gnutls_priority_init(void);
extern int tlshd_gnutls_priority_set(gnutls_session_t session,
				     struct tlshd_handshake_parms *parms,
				     unsigned int psk_len);
extern void tlshd_gnutls_priority_deinit(void);

/* log.c */
extern void tlshd_log_init(const char *progname);
extern void tlshd_log_shutdown(void);
extern void tlshd_log_close(void);

extern void tlshd_log_completion(struct tlshd_handshake_parms *parms);
extern void tlshd_log_debug(const char *fmt, ...);
extern void tlshd_log_notice(const char *fmt, ...);
extern void tlshd_log_error(const char *fmt, ...);
extern void tlshd_log_perror(const char *prefix);
extern void tlshd_log_gai_error(int error);

extern void tlshd_log_cert_verification_error(gnutls_session_t session);
extern void tlshd_log_gnutls_error(int error);
extern void tlshd_gnutls_log_func(int level, const char *msg);
extern void tlshd_gnutls_audit_func(gnutls_session_t session, const char *msg);

void tlshd_log_gerror(const char *msg, GError *error);
void tlshd_log_nl_error(const char *msg, int err);

/* netlink.c */
extern void tlshd_genl_dispatch(void);
extern int tlshd_genl_get_handshake_parms(struct tlshd_handshake_parms *parms);
extern void tlshd_genl_done(struct tlshd_handshake_parms *parms);

/* server.c */
extern void tlshd_tls13_serverhello_handshake(struct tlshd_handshake_parms *parms);
extern void tlshd_quic_serverhello_handshake(struct tlshd_handshake_parms *parms);

#ifdef HAVE_GNUTLS_QUIC
#include <linux/quic.h>

#define TLSHD_QUIC_MAX_DATA_LEN		4096
#define TLSHD_QUIC_MAX_ALPNS_LEN	128

struct tlshd_quic_msg {
	struct tlshd_quic_msg *next;
	uint8_t data[TLSHD_QUIC_MAX_DATA_LEN];
	uint32_t len;
	uint8_t level;
};

struct tlshd_quic_conn {
	struct tlshd_handshake_parms *parms;
	char alpns[TLSHD_QUIC_MAX_ALPNS_LEN];
	uint8_t ticket[TLSHD_QUIC_MAX_DATA_LEN];
	uint32_t ticket_len;
	uint32_t cipher;

	gnutls_session_t session;
	uint8_t recv_ticket:1;
	uint8_t completed:1;
	uint8_t cert_req:2;
	uint8_t is_serv:1;
	uint32_t errcode;
	timer_t timer;

	struct tlshd_quic_msg *send_list;
	struct tlshd_quic_msg *send_last;
	struct tlshd_quic_msg recv_msg;
};

/* quic.c */
extern int tlshd_quic_conn_create(struct tlshd_quic_conn **conn_p,
				  struct tlshd_handshake_parms *parms);
extern void tlshd_quic_conn_destroy(struct tlshd_quic_conn *conn);
extern void tlshd_quic_start_handshake(struct tlshd_quic_conn *conn);
#endif

#define TLS_DEFAULT_PRIORITIES	(NULL)
#define TLS_DEFAULT_PSK_TYPE	"psk"
#define TLS_NO_PEERID		(0)
#define TLS_NO_CERT		(0)
#define TLS_NO_PRIVKEY		(0)
/* Max number of (chained) certs to load */
#define TLSHD_MAX_CERTS		10
