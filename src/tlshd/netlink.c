/**
 * @file netlink.c
 * @brief Handle communication with the kernel via netlink
 *
 * @copyright
 * Copyright (c) 2023 Oracle and/or its affiliates.
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signalfd.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <linux/tls.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/version.h>

#include <glib.h>

#include "tlshd.h"
#include "netlink.h"

/**
 * @var unsigned int tlshd_delay_done
 * Global number of seconds to delay each handshake completion
 */
unsigned int tlshd_delay_done;

/**
 * @brief Open a netlink socket
 * @param [out]    sock  A netlink socket descriptor
 *
 * @retval  0        Success; caller must close "sock" with tlshd_genl_sock_close
 * @retval  ENOMEM   Failed to allocate the socket
 * @retval  ENOLINK  Failed to connect to the netlink service
 */
static int tlshd_genl_sock_open(struct nl_sock **sock)
{
	struct nl_sock *nls;
	int err, ret;

	ret = ENOMEM;
	nls = nl_socket_alloc();
	if (!nls) {
		tlshd_log_error("Failed to allocate netlink socket.");
		goto out;
	}

	ret = ENOLINK;
	err = genl_connect(nls);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("genl_connect", err);
		nl_socket_free(nls);
		goto out;
	}

	*sock = nls;
	ret = 0;
out:
	return ret;
}

/**
 * @brief Close a netlink socket
 * @param[in]     nls  A netlink socket descriptor
 */
static void tlshd_genl_sock_close(struct nl_sock *nls)
{
	if (!nls)
		return;

	nl_close(nls);
	nl_socket_free(nls);
}

/**
 * @var struct nla_policy tlshd_accept_nl_policy
 * Netlink policies for ACCEPT arguments
 */
#if LIBNL_VER_NUM >= LIBNL_VER(3,5)
static const struct nla_policy
#else
static struct nla_policy
#endif
tlshd_accept_nl_policy[HANDSHAKE_A_ACCEPT_MAX + 1] = {
	[HANDSHAKE_A_ACCEPT_SOCKFD]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_HANDLER_CLASS]	= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE]	= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_TIMEOUT]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_AUTH_MODE]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_PEER_IDENTITY]	= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_CERTIFICATE]	= { .type = NLA_NESTED, },
	[HANDSHAKE_A_ACCEPT_PEERNAME]		= { .type = NLA_STRING, },
	[HANDSHAKE_A_ACCEPT_KEYRING]		= { .type = NLA_U32, },
};

/**
 * @var struct nl_sock *tlshd_notification_nls
 * Netlink socket on which notification events arrive
 */
static struct nl_sock *tlshd_notification_nls;

/**
 * @var sigset_t tlshd_sig_poll_mask
 * Daemon's signal poll mask
 */
static sigset_t tlshd_sig_poll_mask;

/**
 * @var int tlshd_sig_poll_fd
 * Daemon's signal poll file descriptor
 */
static int tlshd_sig_poll_fd;

/**
 * @brief Process one netlink notification event
 * @param[in]     msg  A netlink event to be handled
 * @param[in]     arg  Additional arguments
 *
 * @retval NL_OK    Proceed with the next message
 * @retval NL_SKIP  Skip this message.
 * @retval NL_STOP  Stop and discard remaining messages.
 */
static int tlshd_genl_event_handler(struct nl_msg *msg,
				    __attribute__ ((unused)) void *arg)
{
	struct nlattr *tb[HANDSHAKE_A_ACCEPT_MAX + 1];
	int err;

	err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, HANDSHAKE_A_ACCEPT_MAX,
			    tlshd_accept_nl_policy);
	if (err < 0) {
		tlshd_log_nl_error("genlmsg_parse", err);
		return NL_SKIP;
	}

	if (!tb[HANDSHAKE_A_ACCEPT_HANDLER_CLASS])
		return NL_SKIP;
	if (nla_get_u32(tb[HANDSHAKE_A_ACCEPT_HANDLER_CLASS]) !=
	    HANDSHAKE_HANDLER_CLASS_TLSHD)
		return NL_SKIP;

	if (!fork()) {
		/* child */
		close(tlshd_sig_poll_fd);
		sigprocmask(SIG_UNBLOCK, &tlshd_sig_poll_mask, NULL);

		nlmsg_free(msg);
		tlshd_genl_sock_close(tlshd_notification_nls);

		tlshd_service_socket();

		tlshd_gnutls_priority_deinit();
		tlshd_config_shutdown();
		exit(EXIT_SUCCESS);
	}

	return NL_SKIP;
}

/**
 * @brief Handle notification events
 */
void tlshd_genl_dispatch(void)
{
	struct pollfd poll_fds[2];
	int err, mcgrp;

	/* Initialise signal poll mask */
	sigemptyset(&tlshd_sig_poll_mask);
	sigaddset(&tlshd_sig_poll_mask, SIGINT);
	sigaddset(&tlshd_sig_poll_mask, SIGTERM);

	err = tlshd_genl_sock_open(&tlshd_notification_nls);
	if (err)
		return;

	nl_socket_modify_cb(tlshd_notification_nls, NL_CB_VALID, NL_CB_CUSTOM,
			    tlshd_genl_event_handler, NULL);

	/* Let the kernel know we are running */
	mcgrp = genl_ctrl_resolve_grp(tlshd_notification_nls, HANDSHAKE_FAMILY_NAME,
				      HANDSHAKE_MCGRP_TLSHD);
	if (mcgrp < 0) {
		tlshd_log_error("Kernel handshake service is not available");
		goto out_close;
	}
	err = nl_socket_add_membership(tlshd_notification_nls, mcgrp);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_socket_add_membership", err);
		goto out_close;
	}

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		tlshd_log_perror("signal");
		goto out_close;
	}

	nl_socket_disable_seq_check(tlshd_notification_nls);

	err = nl_socket_set_nonblocking(tlshd_notification_nls);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_socket_set_nonblocking", err);
		goto out_close;
	}

	if (sigprocmask(SIG_BLOCK, &tlshd_sig_poll_mask, NULL)) {
		tlshd_log_perror("sigprocmask");
		goto out_close;
	}

	tlshd_sig_poll_fd = signalfd(-1, &tlshd_sig_poll_mask,
				     SFD_NONBLOCK | SFD_CLOEXEC);
	if (tlshd_sig_poll_fd < 0) {
		tlshd_log_perror("signalfd");
		goto out_close;
	}

	poll_fds[0].fd = nl_socket_get_fd(tlshd_notification_nls);
	poll_fds[0].events = POLLIN;
	poll_fds[1].fd = tlshd_sig_poll_fd;
	poll_fds[1].events = POLLIN;

	while (poll(poll_fds, ARRAY_SIZE(poll_fds), -1) >= 0) {
		if (poll_fds[1].revents)
			/* exit signal received */
			break;

		if (poll_fds[0].revents) {
			err = nl_recvmsgs_default(tlshd_notification_nls);
			if (err < 0) {
				tlshd_log_nl_error("nl_recvmsgs", err);
				break;
			}
		}
	};

	close(tlshd_sig_poll_fd);

out_close:
	tlshd_genl_sock_close(tlshd_notification_nls);
}

/**
 * @brief Extract the key serial number of the key with the remote peerid
 * @param[in]     parms  Handshake parameters
 * @param[in]     head   List of nlattrs to parse
 */
static void tlshd_parse_peer_identity(struct tlshd_handshake_parms *parms,
				      struct nlattr *head)
{
	key_serial_t peerid;

	if (!head) {
		tlshd_log_debug("No peer identities found\n");
		return;
	}

	peerid = nla_get_s32(head);
	g_array_append_val(parms->peerids, peerid);
}

/**
 * @var struct nla_policy tlshd_x509_nl_policy
 * Netlink policies for x.509 key serial numbers
 */
#if LIBNL_VER_NUM >= LIBNL_VER(3,5)
static const struct nla_policy
#else
static struct nla_policy
#endif
tlshd_x509_nl_policy[HANDSHAKE_A_X509_MAX + 1] = {
	[HANDSHAKE_A_X509_CERT]		= { .type = NLA_U32, },
	[HANDSHAKE_A_X509_PRIVKEY]	= { .type = NLA_U32, },
};

/**
 * @brief Extract the key serial number of the key with the cert / privkey
 * @param[in]     parms  Handshake parameters
 * @param[in]     head   List of nlattrs to parse
 */
static void tlshd_parse_certificate(struct tlshd_handshake_parms *parms,
				     struct nlattr *head)
{
	struct nlattr *tb[HANDSHAKE_A_X509_MAX + 1];
	int err;

	if (!head) {
		tlshd_log_debug("No certificates found\n");
		return;
	}

	err = nla_parse_nested(tb, HANDSHAKE_A_X509_MAX, head,
			       tlshd_x509_nl_policy);
	if (err < 0)
		return;

	if (tb[HANDSHAKE_A_X509_CERT])
		parms->x509_cert = nla_get_s32(tb[HANDSHAKE_A_X509_CERT]);
	if (tb[HANDSHAKE_A_X509_PRIVKEY])
		parms->x509_privkey = nla_get_s32(tb[HANDSHAKE_A_X509_PRIVKEY]);
}

/**
 * @brief Process an ACCESS argument
 * @param[in]     msg  Message to be processed
 * @param[out]    arg  Handshake parms to be filled in
 *
 * @retval NL_OK    Proceed with the next message
 * @retval NL_SKIP  Skip this message.
 * @retval NL_STOP  Stop and discard remaining messages.
 */
static int tlshd_genl_valid_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[HANDSHAKE_A_ACCEPT_MAX + 1];
	struct tlshd_handshake_parms *parms = arg;
	struct sockaddr_storage addr;
	struct sockaddr *sap = NULL;
	const char *peername = NULL;
	socklen_t salen, optlen;
	int err;

	tlshd_log_debug("Parsing a valid netlink message\n");

	err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, HANDSHAKE_A_ACCEPT_MAX,
			    tlshd_accept_nl_policy);
	if (err < 0) {
		tlshd_log_nl_error("genlmsg_parse", err);
		return NL_STOP;
	}

	if (tb[HANDSHAKE_A_ACCEPT_SOCKFD]) {
		char buf[NI_MAXHOST];
		int proto;

		parms->sockfd = nla_get_s32(tb[HANDSHAKE_A_ACCEPT_SOCKFD]);

		salen = sizeof(addr);
		sap = (struct sockaddr *)&addr;
		if (getpeername(parms->sockfd, sap, &salen) == -1) {
			tlshd_log_perror("getpeername");
			return NL_STOP;
		}
		err = getnameinfo(sap, salen, buf, sizeof(buf),
				  NULL, 0, NI_NUMERICHOST);
		if (err) {
			tlshd_log_gai_error(err);
			return NL_STOP;
		}
		parms->peeraddr = strdup(buf);

		optlen = sizeof(proto);
		if (getsockopt(parms->sockfd, SOL_SOCKET, SO_PROTOCOL,
			       &proto, &optlen) == -1) {
			tlshd_log_perror("getsockopt (SO_PROTOCOL)");
			return NL_STOP;
		}
		parms->ip_proto = proto;
	}
	if (tb[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE])
		parms->handshake_type = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE]);
	if (tb[HANDSHAKE_A_ACCEPT_PEERNAME])
		peername = nla_get_string(tb[HANDSHAKE_A_ACCEPT_PEERNAME]);
	if (tb[HANDSHAKE_A_ACCEPT_KEYRING])
		parms->keyring = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_KEYRING]);
	if (tb[HANDSHAKE_A_ACCEPT_TIMEOUT])
		parms->timeout_ms = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_TIMEOUT]);
	if (tb[HANDSHAKE_A_ACCEPT_AUTH_MODE])
		parms->auth_mode = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_AUTH_MODE]);

	if (parms->keyring) {
		err = keyctl_link(parms->keyring, KEY_SPEC_SESSION_KEYRING);
		if (err < 0) {
			tlshd_log_debug("Failed to link keyring %lx error %d\n",
					parms->keyring, errno);
		}
	}

	tlshd_parse_peer_identity(parms, tb[HANDSHAKE_A_ACCEPT_PEER_IDENTITY]);
	tlshd_parse_certificate(parms, tb[HANDSHAKE_A_ACCEPT_CERTIFICATE]);

	if (peername)
		parms->peername = strdup(peername);
	else if (sap) {
		char buf[NI_MAXHOST];

		err = getnameinfo(sap, salen, buf, sizeof(buf),
				  NULL, 0, NI_NAMEREQD);
		if (err) {
			tlshd_log_gai_error(err);
			return NL_STOP;
		}
		parms->peername = strdup(buf);
	}

	return NL_SKIP;
}

/**
 * @var struct tlshd_handshake_parms tlshd_default_handshake_parms
 * Starting parameter values for each handshake
 */
static const struct tlshd_handshake_parms tlshd_default_handshake_parms = {
	.peername		= NULL,
	.peeraddr		= NULL,
	.sockfd			= -1,
	.ip_proto		= -1,
	.handshake_type		= HANDSHAKE_MSG_TYPE_UNSPEC,
	.timeout_ms		= GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT,
	.auth_mode		= HANDSHAKE_AUTH_UNSPEC,
	.x509_cert		= TLS_NO_CERT,
	.x509_privkey		= TLS_NO_PRIVKEY,
	.peerids		= NULL,
	.remote_peerids		= NULL,
	.session_status		= EIO,
};

/**
 * @brief Retrieve handshake parameters
 * @param[in]     parms  Buffer to fill in with parameters
 *
 * Caller must release handshake resources by calling
 * tlshd_genl_put_handshake_parms when finished.
 *
 * @returns 0 if handshake parameters were retrieved successfully.
 * Otherwise a positive errno is returned, and the content of
 * "parms" is indeterminant.
 */
int tlshd_genl_get_handshake_parms(struct tlshd_handshake_parms *parms)
{
	const struct nlmsghdr *hdr;
	int family_id, err, ret;
	struct nl_sock *nls;
	struct nl_msg *msg;

	tlshd_log_debug("Querying the handshake service\n");

	*parms = tlshd_default_handshake_parms;

	parms->peerids = g_array_new(FALSE, FALSE, sizeof(key_serial_t));
	parms->remote_peerids = g_array_new(FALSE, FALSE, sizeof(key_serial_t));

	ret = tlshd_genl_sock_open(&nls);
	if (ret)
		return ret;

	ret = ESRCH;
	family_id = genl_ctrl_resolve(nls, HANDSHAKE_FAMILY_NAME);
	if (family_id < 0) {
		tlshd_log_error("Failed to resolve netlink service.");
		goto out_close;
	}

	nl_socket_modify_cb(nls, NL_CB_VALID, NL_CB_CUSTOM,
			    tlshd_genl_valid_handler, parms);

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_close;
	}

	ret = EIO;
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
			  0, 0, HANDSHAKE_CMD_ACCEPT, 0);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_msgfree;
	}

	err = nla_put_u32(msg, HANDSHAKE_A_ACCEPT_HANDLER_CLASS,
			  HANDSHAKE_HANDLER_CLASS_TLSHD);
	if (err < 0) {
		tlshd_log_nl_error("nla_put handler class", err);
		goto out_msgfree;
	}

	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_msgfree;
	}

	ret = EINVAL;
	err = nl_recvmsgs_default(nls);
	if (err < 0) {
		tlshd_log_nl_error("nl_recvmsgs", err);
		goto out_msgfree;
	}

	ret = 0;

out_msgfree:
	nlmsg_free(msg);
out_close:
	tlshd_genl_sock_close(nls);
	return ret;
}

/**
 * @brief Release handshake resources
 * @param[in]     parms  Handshake parameters to be released
 */
void tlshd_genl_put_handshake_parms(struct tlshd_handshake_parms *parms)
{
	if (parms->keyring)
		keyctl_unlink(parms->keyring, KEY_SPEC_SESSION_KEYRING);
	g_array_free(parms->peerids, TRUE);
	g_array_free(parms->remote_peerids, TRUE);
	free(parms->peername);
	free(parms->peeraddr);
}

/**
 * @brief Format all remote peerid arguments
 * @param[in]     msg
 * @param[in]     parms  Handshake parameters
 *
 * retval 0   Formatted all remote peerid arguments successfully
 * retval -1  Failed to format
 */
static int tlshd_genl_put_remote_peerids(struct nl_msg *msg,
					 struct tlshd_handshake_parms *parms)
{
	key_serial_t peerid;
	guint i;

	for (i = 0; i < parms->remote_peerids->len; i++) {
		int err;

		peerid = g_array_index(parms->remote_peerids, key_serial_t, i);
		err = nla_put_s32(msg, HANDSHAKE_A_DONE_REMOTE_AUTH, peerid);
		if (err < 0) {
			tlshd_log_nl_error("nla_put peer id", err);
			return -1;
		}
	}
	return 0;
}

/**
 * @brief Indicate handshake has completed successfully
 * @param[in]     parms  Buffer filled in with parameters
 */
void tlshd_genl_done(struct tlshd_handshake_parms *parms)
{
	const struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nl_msg *msg;
	int family_id, err;

	if (parms->sockfd == -1)
		return;

	err = tlshd_genl_sock_open(&nls);
	if (err)
		return;

	family_id = genl_ctrl_resolve(nls, HANDSHAKE_FAMILY_NAME);
	if (family_id < 0) {
		tlshd_log_nl_error("genl_ctrl_resolve", err);
		goto out_close;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		tlshd_log_error("Failed to allocate message buffer.");
		goto out_close;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
			  0, 0, HANDSHAKE_CMD_DONE, 0);
	if (!hdr) {
		tlshd_log_error("Failed to set up message header.");
		goto out_free;
	}

	err = nla_put_u32(msg, HANDSHAKE_A_DONE_STATUS,
			  parms->session_status);
	if (err) {
		tlshd_log_nl_error("nla_put sess_status", err);
		goto out_free;
	}

	err = nla_put_s32(msg, HANDSHAKE_A_DONE_SOCKFD, parms->sockfd);
	if (err < 0) {
		tlshd_log_nl_error("nla_put sockfd", err);
		goto out_free;
	}
	if (parms->session_status)
		goto sendit;

	err = tlshd_genl_put_remote_peerids(msg, parms);
	if (err < 0)
		goto out_free;

sendit:
	if (tlshd_delay_done) {
		/* Undocumented tlshd.conf parameter:
		 * delay DONE downcall by N seconds */
		tlshd_log_debug("delaying %d second(s)", tlshd_delay_done);
		sleep(tlshd_delay_done);
	}

	nl_socket_disable_auto_ack(nls);
	err = nl_send_auto(nls, msg);
	if (err < 0) {
		tlshd_log_nl_error("nl_send_auto", err);
		goto out_free;
	}

out_free:
	nlmsg_free(msg);
out_close:
	tlshd_genl_sock_close(nls);
}
