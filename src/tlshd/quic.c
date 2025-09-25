/*
 * Perform a QUIC server or client side handshake.
 *
 * Copyright (c) 2024 Red Hat, Inc.
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

#include <config.h>

#include <gnutls/abstract.h>
#include <sys/socket.h>
#include <linux/tls.h>
#include <keyutils.h>
#include <stdbool.h>
#include <unistd.h>
#include <glib.h>

#include "tlshd.h"

#ifdef HAVE_GNUTLS_QUIC
static void quic_timer_handler(union sigval arg)
{
	struct tlshd_quic_conn *conn = arg.sival_ptr;

	tlshd_log_error("conn timeout error %d", ETIMEDOUT);
	conn->errcode = ETIMEDOUT;
}

static int quic_conn_setup_timer(struct tlshd_quic_conn *conn)
{
	uint64_t msec = conn->parms->timeout_ms;
	struct itimerspec its = {};
	struct sigevent sev = {};

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = quic_timer_handler;
	sev.sigev_value.sival_ptr = conn;
	if (timer_create(CLOCK_REALTIME, &sev, &conn->timer)) {
		tlshd_log_error("timer creation error %d", errno);
		return -1;
	}

	its.it_value.tv_sec  = msec / 1000;
	its.it_value.tv_nsec = (msec % 1000) * 1000000;
	if (timer_settime(conn->timer, 0, &its, NULL)) {
		tlshd_log_error("timer setup error %d", errno);
		return -1;
	}
	return 0;
}

static void quic_conn_delete_timer(struct tlshd_quic_conn *conn)
{
	timer_delete(conn->timer);
}

static uint32_t quic_get_tls_cipher_type(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
		return TLS_CIPHER_AES_GCM_128;
	case GNUTLS_CIPHER_AES_128_CCM:
		return TLS_CIPHER_AES_CCM_128;
	case GNUTLS_CIPHER_AES_256_GCM:
		return TLS_CIPHER_AES_GCM_256;
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return TLS_CIPHER_CHACHA20_POLY1305;
	default:
		tlshd_log_notice("%s: %d", __func__, cipher);
		return 0;
	}
}

static enum quic_crypto_level quic_get_crypto_level(gnutls_record_encryption_level_t level)
{
	switch (level) {
	case GNUTLS_ENCRYPTION_LEVEL_INITIAL:
		return QUIC_CRYPTO_INITIAL;
	case GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE:
		return QUIC_CRYPTO_HANDSHAKE;
	case GNUTLS_ENCRYPTION_LEVEL_APPLICATION:
		return QUIC_CRYPTO_APP;
	case GNUTLS_ENCRYPTION_LEVEL_EARLY:
		return QUIC_CRYPTO_EARLY;
	default:
		tlshd_log_notice("%s: %d", __func__, level);
		return QUIC_CRYPTO_MAX;
	}
}

static int quic_secret_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
			    const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_cipher_algorithm_t type  = gnutls_cipher_get(session);
	struct quic_crypto_secret secret = {};
	int sockfd, len = sizeof(secret);

	if (conn->completed)
		return 0;

	if (level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
		type = gnutls_early_cipher_get(session);

	sockfd = conn->parms->sockfd;
	secret.level = quic_get_crypto_level(level);
	secret.type = quic_get_tls_cipher_type(type);
	if (tx_secret) {
		secret.send = 1;
		memcpy(secret.secret, tx_secret, secretlen);
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			tlshd_log_error("socket setsockopt tx secret error %d %u", errno, level);
			return -1;
		}
	}
	if (rx_secret) {
		secret.send = 0;
		memcpy(secret.secret, rx_secret, secretlen);
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			tlshd_log_error("socket setsockopt rx secret error %d %u", errno, level);
			return -1;
		}
		if (secret.level == QUIC_CRYPTO_APP) {
			if (conn->is_serv) {
				int ret;

				ret = gnutls_session_ticket_send(session, 1, 0);
				if (ret) {
					tlshd_log_gnutls_error(ret);
					return ret;
				}
			}
			conn->completed = 1;
		}
	}
	tlshd_log_debug("  Secret func: %u %u %u", secret.level, !!tx_secret, !!rx_secret);
	return 0;
}

static int quic_alert_read_func(gnutls_session_t session,
				gnutls_record_encryption_level_t gtls_level,
				gnutls_alert_level_t alert_level,
				gnutls_alert_description_t alert_desc)
{
	tlshd_log_notice("%s: %u %u %u %u", __func__,
			 !!session, gtls_level, alert_level, alert_desc);
	return 0;
}

static int quic_tp_recv_func(gnutls_session_t session, const uint8_t *buf, size_t len)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	int sockfd = conn->parms->sockfd;

	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, len)) {
		tlshd_log_error("socket setsockopt transport_param_ext error %d", errno);
		return -1;
	}
	return 0;
}

static int quic_tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	int ret, sockfd = conn->parms->sockfd;
	uint8_t buf[256];
	unsigned int len;

	len = sizeof(buf);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, &len)) {
		tlshd_log_error("socket getsockopt transport_param_ext error %d", errno);
		return -1;
	}

	ret = gnutls_buffer_append_data(extdata, buf, len);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		return -1;
	}

	return 0;
}

static int quic_read_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
			  gnutls_handshake_description_t htype, const void *data, size_t datalen)
{
	struct tlshd_quic_conn *conn = gnutls_session_get_ptr(session);
	struct tlshd_quic_msg *msg;
	uint32_t len = datalen;

	if (htype == GNUTLS_HANDSHAKE_KEY_UPDATE)
		return 0;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		tlshd_log_debug("msg malloc error %d", ENOMEM);
		return -1;
	}
	memset(msg, 0, sizeof(*msg));
	msg->len = len;
	memcpy(msg->data, data, msg->len);

	msg->level = quic_get_crypto_level(level);
	if (!conn->send_list)
		conn->send_list = msg;
	else
		conn->send_last->next = msg;
	conn->send_last = msg;

	tlshd_log_debug("  Read func: %u %u %u", level, htype, datalen);
	return 0;
}

static char quic_priority[] =
	"%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+";

static int quic_session_set_priority(gnutls_session_t session, uint32_t cipher)
{
	char p[136] = {};
	int ret;

	memcpy(p, quic_priority, strlen(quic_priority));
	switch (cipher) {
	case TLS_CIPHER_AES_GCM_128:
		strcat(p, "AES-128-GCM");
		break;
	case TLS_CIPHER_AES_GCM_256:
		strcat(p, "AES-256-GCM");
		break;
	case TLS_CIPHER_AES_CCM_128:
		strcat(p, "AES-128-CCM");
		break;
	case TLS_CIPHER_CHACHA20_POLY1305:
		strcat(p, "CHACHA20-POLY1305");
		break;
	default:
		strcat(p, "AES-128-GCM:+AES-256-GCM:+AES-128-CCM:+CHACHA20-POLY1305");
	}

	ret = gnutls_priority_set_direct(session, p, NULL);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		return -1;
	}
	return 0;
}

static int quic_session_set_alpns(gnutls_session_t session, char *alpn_data)
{
	gnutls_datum_t alpns[TLSHD_QUIC_MAX_ALPNS_LEN / 2];
	char *alpn = strtok(alpn_data, ",");
	int count = 0, ret;

	while (alpn) {
		while (*alpn == ' ')
			alpn++;
		alpns[count].data = (unsigned char *)alpn;
		alpns[count].size = strlen(alpn);
		count++;
		alpn = strtok(NULL, ",");
	}

	ret = gnutls_alpn_set_protocols(session, alpns, count, GNUTLS_ALPN_MANDATORY);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		return -1;
	}
	return 0;
}

static gnutls_record_encryption_level_t quic_get_encryption_level(uint8_t level)
{
	switch (level) {
	case QUIC_CRYPTO_INITIAL:
		return GNUTLS_ENCRYPTION_LEVEL_INITIAL;
	case QUIC_CRYPTO_HANDSHAKE:
		return GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE;
	case QUIC_CRYPTO_APP:
		return GNUTLS_ENCRYPTION_LEVEL_APPLICATION;
	case QUIC_CRYPTO_EARLY:
		return GNUTLS_ENCRYPTION_LEVEL_EARLY;
	default:
		tlshd_log_notice("%s: %d", __func__, level);
		return GNUTLS_ENCRYPTION_LEVEL_APPLICATION + 1;
	}
}

static int quic_conn_get_config(struct tlshd_quic_conn *conn)
{
	int sockfd = conn->parms->sockfd;
	struct quic_config config = {};
	unsigned int len;

	len = sizeof(conn->alpns);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, conn->alpns, &len)) {
		tlshd_log_error("socket getsockopt alpn error %d", errno);
		return -1;
	}
	len = sizeof(conn->ticket);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, conn->ticket, &len)) {
		tlshd_log_error("socket getsockopt session ticket error %d", errno);
		return -1;
	}
	conn->ticket_len = len;
	len = sizeof(config);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONFIG, &config, &len)) {
		tlshd_log_error("socket getsockopt config error %d", errno);
		return -1;
	}
	conn->recv_ticket = config.receive_session_ticket;
	conn->cert_req = config.certificate_request;
	conn->cipher = config.payload_cipher_type;
	return 0;
}

static int quic_handshake_sendmsg(int sockfd, struct tlshd_quic_msg *msg)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	int flags = 0;

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg->data;
	iov.iov_len = msg->len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;
	if (msg->next)
		flags = MSG_MORE;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
	info->crypto_level = msg->level;

	return sendmsg(sockfd, &outmsg, flags);
}

static int quic_handshake_recvmsg(int sockfd, struct tlshd_quic_msg *msg)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info info;
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int ret;

	msg->len = 0;
	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg->data;
	iov.iov_len = sizeof(msg->data);

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	ret = recvmsg(sockfd, &inmsg, MSG_DONTWAIT);
	if (ret < 0)
		return ret;
	msg->len = ret;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (SOL_QUIC == cmsg->cmsg_level && QUIC_HANDSHAKE_INFO == cmsg->cmsg_type)
			break;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
		msg->level = info.crypto_level;
	}

	return ret;
}

static int quic_handshake_completed(const struct tlshd_quic_conn *conn)
{
	return conn->completed || conn->errcode;
}

static int quic_handshake_crypto_data(const struct tlshd_quic_conn *conn,
				      uint8_t level, const uint8_t *data,
				      size_t datalen)
{
	gnutls_session_t session = conn->session;
	int ret;

	level = quic_get_encryption_level(level);
	if (datalen > 0) {
		ret = gnutls_handshake_write(session, level, data, datalen);
		if (ret) {
			if (!gnutls_error_is_fatal(ret))
				return 0;
			goto err;
		}
	}

	ret = gnutls_handshake(session);
	if (ret < 0) {
		if (!gnutls_error_is_fatal(ret))
			return 0;
		goto err;
	}
	return 0;
err:
	gnutls_alert_send_appropriate(session, ret);
	tlshd_log_gnutls_error(ret);
	return -1;
}

/**
 * tlshd_quic_conn_create - Create a context for QUIC handshake
 * @conn_p: pointer to accept the QUIC handshake context created
 * @parms: handshake parameters
 *
 * Returns: %0 on success, or a negative error code
 */
int tlshd_quic_conn_create(struct tlshd_quic_conn **conn_p, struct tlshd_handshake_parms *parms)
{
	struct tlshd_quic_conn *conn;
	int ret;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		tlshd_log_error("conn malloc error %d", ENOMEM);
		return -ENOMEM;
	}

	memset(conn, 0, sizeof(*conn));
	conn->parms = parms;

	if (quic_conn_get_config(conn)) {
		ret = -errno;
		goto err;
	}

	if (quic_conn_setup_timer(conn)) {
		ret = -errno;
		goto err;
	}

	*conn_p = conn;
	return 0;
err:
	tlshd_quic_conn_destroy(conn);
	return ret;
}

/**
 * tlshd_quic_conn_destroy - Destroy a context for QUIC handshake
 * @conn: QUIC handshake context to destroy
 *
 */
void tlshd_quic_conn_destroy(struct tlshd_quic_conn *conn)
{
	struct tlshd_quic_msg *msg = conn->send_list;

	while (msg) {
		conn->send_list = msg->next;
		free(msg);
		msg = conn->send_list;
	}

	quic_conn_delete_timer(conn);
	gnutls_deinit(conn->session);
	free(conn);
}

#define QUIC_TLSEXT_TP_PARAM	0x39u

static int tlshd_quic_session_configure(struct tlshd_quic_conn *conn)
{
	gnutls_session_t session = conn->session;
	int ret;

	if (quic_session_set_priority(session, conn->cipher))
		return -1;

	if (conn->alpns[0] && quic_session_set_alpns(session, conn->alpns))
		return -1;

	gnutls_handshake_set_secret_function(session, quic_secret_func);
	gnutls_handshake_set_read_function(session, quic_read_func);
	gnutls_alert_set_read_function(session, quic_alert_read_func);

	ret = gnutls_session_ext_register(
		session, "QUIC Transport Parameters", QUIC_TLSEXT_TP_PARAM,
		GNUTLS_EXT_TLS, quic_tp_recv_func, quic_tp_send_func, NULL, NULL, NULL,
		GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		return -1;
	}
	return 0;
}

static void tlshd_quic_recv_session_ticket(struct tlshd_quic_conn *conn)
{
	gnutls_session_t session = conn->session;
	int i, ret, sockfd = conn->parms->sockfd;
	unsigned int len;
	size_t size;

	if (conn->is_serv || !conn->recv_ticket)
		return;

	for (i = 0; i < 10 * conn->recv_ticket; i++) { /* wait and try for conn->recv_ticket secs */
		len = sizeof(conn->ticket);
		ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, conn->ticket, &len);
		if (ret) {
			tlshd_log_error("socket getsockopt session ticket error %d", errno);
			conn->errcode = errno;
			return;
		}
		if (len)
			break;
		usleep(100000);
	}
	if (i == 10 * conn->recv_ticket)
		return;

	/* process new session ticket msg and get the generated session data */
	if (quic_handshake_crypto_data(conn, QUIC_CRYPTO_APP, conn->ticket, len)) {
		conn->errcode = EACCES;
		return;
	}

	size = sizeof(conn->ticket);
	ret = gnutls_session_get_data(session, conn->ticket, &size);
	if (ret) {
		tlshd_log_gnutls_error(ret);
		conn->errcode = EACCES;
		return;
	}

	/* set it back to kernel for session resumption of next connection */
	len = size;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, conn->ticket, len);
	if (ret) {
		tlshd_log_error("socket setsockopt session ticket error %d %u", errno, len);
		conn->errcode = errno;
	}
}

/**
 * tlshd_quic_start_handshake - Drive the handshake interaction
 * @conn: QUIC handshake context
 *
 */
void tlshd_quic_start_handshake(struct tlshd_quic_conn *conn)
{
	int ret, sockfd = conn->parms->sockfd;
	struct timeval tv = {1, 0};
	struct tlshd_quic_msg *msg;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	if (tlshd_quic_session_configure(conn)) {
		conn->errcode = EACCES;
		return;
	}

	if (!conn->is_serv) {
		if (quic_handshake_crypto_data(conn, QUIC_CRYPTO_INITIAL, NULL, 0)) {
			conn->errcode = EACCES;
			return;
		}

		msg = conn->send_list;
		while (msg) {
			tlshd_log_debug("< Handshake SEND: %d %d", msg->len, msg->level);
			ret = quic_handshake_sendmsg(sockfd, msg);
			if (ret < 0) {
				tlshd_log_error("socket sendmsg error %d", errno);
				conn->errcode = errno;
				return;
			}
			conn->send_list = msg->next;
			free(msg);
			msg = conn->send_list;
		}
	}

	while (!quic_handshake_completed(conn)) {
		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0) {
			conn->errcode = errno;
			return tlshd_log_error("socket select error %d", errno);
		}
		msg = &conn->recv_msg;
		while (!quic_handshake_completed(conn)) {
			ret = quic_handshake_recvmsg(sockfd, msg);
			if (ret <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				conn->errcode = errno;
				return tlshd_log_error("socket recvmsg error %d", errno);
			}
			tlshd_log_debug("> Handshake RECV: %u %u", msg->len, msg->level);
			if (quic_handshake_crypto_data(conn, msg->level, msg->data, msg->len)) {
				conn->errcode = EACCES;
				return;
			}
		}

		msg = conn->send_list;
		while (msg) {
			tlshd_log_debug("< Handshake SEND: %u %u", msg->len, msg->level);
			ret = quic_handshake_sendmsg(sockfd, msg);
			if (ret < 0) {
				conn->errcode = errno;
				return tlshd_log_error("socket sendmsg error %d", errno);
			}
			conn->send_list = msg->next;
			free(msg);
			msg = conn->send_list;
		}
	}

	tlshd_quic_recv_session_ticket(conn);
}
#endif
