/*
 * Netlink operations for tlshd
 *
 * Copyright (c) 2023 Oracle and/or its affiliates.
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
#include <sys/stat.h>
#include <sys/socket.h>

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

#include <glib.h>

#include "tlshd.h"
#include "netlink.h"

static int tlshd_genl_sock_open(struct nl_sock **sock)
{
	struct nl_sock *nls;
	int err, ret;

	ret = -ENOMEM;
	nls = nl_socket_alloc();
	if (!nls) {
		tlshd_log_error("Failed to allocate netlink socket.");
		goto out;
	}

	ret = -ENOLINK;
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

static void tlshd_genl_sock_close(struct nl_sock *nls)
{
	if (!nls)
		return;

	nl_close(nls);
	nl_socket_free(nls);
}

static const struct nla_policy
tlshd_accept_nl_policy[HANDSHAKE_A_ACCEPT_MAX + 1] = {
	[HANDSHAKE_A_ACCEPT_STATUS]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_SOCKFD]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_HANDLER_CLASS]	= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE]	= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_AUTH]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_GNUTLS_PRIORITIES]	= { .type = NLA_NUL_STRING, },
	[HANDSHAKE_A_ACCEPT_PEERID_LIST]	= { .type = NLA_NESTED, },
	[HANDSHAKE_A_ACCEPT_MY_PRIVKEY]		= { .type = NLA_U32, },
	[HANDSHAKE_A_ACCEPT_MY_PEERID]		= { .type = NLA_U32, },
};

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
		tlshd_service_socket();
		exit(EXIT_SUCCESS);
	}

	return NL_SKIP;
}

/**
 * tlshd_genl_dispatch - handle notification events
 *
 */
void tlshd_genl_dispatch(void)
{
	struct nl_sock *nls;
	int err, mcgrp;

	err = tlshd_genl_sock_open(&nls);
	if (err)
		return;

	nl_socket_modify_cb(nls, NL_CB_VALID, NL_CB_CUSTOM,
			    tlshd_genl_event_handler, NULL);

	/* Let the kernel know we are running */
	mcgrp = genl_ctrl_resolve_grp(nls, HANDSHAKE_FAMILY_NAME,
				      HANDSHAKE_MCGRP_TLSHD);
	if (mcgrp < 0) {
		tlshd_log_nl_error("genl_ctrl_resolve_grp", mcgrp);
		goto out_close;
	}
	err = nl_socket_add_membership(nls, mcgrp);
	if (err != NLE_SUCCESS) {
		tlshd_log_nl_error("nl_socket_add_membership", err);
		goto out_close;
	}

	signal(SIGCHLD, SIG_IGN);
	nl_socket_disable_seq_check(nls);
	while (true) {
		err = nl_recvmsgs_default(nls);
		if (err < 0) {
			tlshd_log_nl_error("nl_recvmsgs", err);
			break;
		}
	};

out_close:
	tlshd_genl_sock_close(nls);
}

static int tlshd_genl_valid_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[HANDSHAKE_A_ACCEPT_MAX + 1];
	struct tlshd_handshake_parms *parms = arg;
	int err;

	err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, HANDSHAKE_A_ACCEPT_MAX,
			    tlshd_accept_nl_policy);
	if (err < 0) {
		tlshd_log_nl_error("genlmsg_parse", err);
		return NL_STOP;
	}

	if (tb[HANDSHAKE_A_ACCEPT_STATUS]) {
		parms->msg_status = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_STATUS]);
		if (parms->msg_status)
			return NL_STOP;
	}

	if (tb[HANDSHAKE_A_ACCEPT_SOCKFD])
		parms->sockfd = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_SOCKFD]);
	if (tb[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE])
		parms->handshake_type = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_MESSAGE_TYPE]);
	if (tb[HANDSHAKE_A_ACCEPT_AUTH])
		parms->auth_type = nla_get_u32(tb[HANDSHAKE_A_ACCEPT_AUTH]);
	if (tb[HANDSHAKE_A_ACCEPT_GNUTLS_PRIORITIES])
		parms->priorities =
			strdup(nla_get_string(tb[HANDSHAKE_A_ACCEPT_GNUTLS_PRIORITIES]));

	switch (parms->auth_type) {
	case HANDSHAKE_AUTH_X509:
		if (tb[HANDSHAKE_A_ACCEPT_PEERID_LIST]) {
			struct nlattr *nla_peerid = NULL;
			int remaining;

			nla_for_each_nested(tb[HANDSHAKE_A_ACCEPT_PEERID_LIST],
					    nla_peerid, remaining) {
				if (!nla_peerid)
					continue;
				if (nla_type(nla_peerid) != HANDSHAKE_A_ACCEPT_MY_PEERID)
					continue;
				if (parms->x509_cert != TLS_NO_PEERID)
					break;
				parms->x509_cert = nla_get_u32(nla_peerid);
			}
		}
		if (tb[HANDSHAKE_A_ACCEPT_MY_PRIVKEY])
			parms->x509_privkey =
				nla_get_u32(tb[HANDSHAKE_A_ACCEPT_MY_PRIVKEY]);
		break;
	case HANDSHAKE_AUTH_PSK:
		if (tb[HANDSHAKE_A_ACCEPT_PEERID_LIST]) {
			struct nlattr *nla_peerid = NULL;
			int remaining, num_peerid = 0;

			nla_for_each_nested(tb[HANDSHAKE_A_ACCEPT_PEERID_LIST],
					    nla_peerid, remaining) {
				key_serial_t *peerid_list, peerid;

				if (!nla_peerid)
					continue;
				if (nla_type(nla_peerid) != HANDSHAKE_A_ACCEPT_MY_PEERID)
					continue;
				peerid = nla_get_u32(nla_peerid);
				peerid_list = gnutls_malloc(sizeof(key_serial_t) * (num_peerid + 1));
				if (!peerid_list)
					return NL_STOP;
				memcpy(peerid_list, parms->peerids,
				       sizeof(key_serial_t) * num_peerid);
				peerid_list[num_peerid] = peerid;
				free(parms->peerids);
				parms->peerids = peerid_list;
				num_peerid++;
				parms->num_peerids = num_peerid;
			}
		}
		break;
	}

	return NL_SKIP;
}

static const struct tlshd_handshake_parms tlshd_default_handshake_parms = {
	.sockfd			= -1,
	.handshake_type		= HANDSHAKE_MSG_TYPE_UNSPEC,
	.auth_type		= HANDSHAKE_AUTH_UNSPEC,
	.priorities		= TLS_DEFAULT_PRIORITIES,
	.x509_cert		= TLS_NO_CERT,
	.x509_privkey		= TLS_NO_PRIVKEY,
	.peerids		= NULL,
	.num_peerids		= 0,
	.msg_status		= 0,
	.session_status		= -EIO,
	.session_peerid		= TLS_NO_PEERID,
};

/**
 * tlshd_genl_get_handshake_parms - Retrieve handshake parameters
 * @parms: buffer to fill in with parameters
 *
 * Returns 0 if handshake parameters were retrieved successfully.
 * Caller must free the string returned in parms->priorities with
 * free(3).
 *
 * Otherwise a negative errno is returned, and the content of
 * @parms is indeterminant.
 */
int tlshd_genl_get_handshake_parms(struct tlshd_handshake_parms *parms)
{
	int family_id, err, ret;
	struct nlmsghdr *hdr;
	struct nl_sock *nls;
	struct nl_msg *msg;

	tlshd_log_debug("Querying the handshake service\n");
	*parms = tlshd_default_handshake_parms;

	ret = tlshd_genl_sock_open(&nls);
	if (ret)
		return ret;

	ret = -ESRCH;
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

	ret = -EIO;
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

	ret = -EINVAL;
	err = nl_recvmsgs_default(nls);
	if (err < 0) {
		tlshd_log_nl_error("nl_recvmsgs", err);
		goto out_msgfree;
	}

	ret = parms->msg_status;

out_msgfree:
	nlmsg_free(msg);
out_close:
	tlshd_genl_sock_close(nls);
	return ret;
}

/* To do: handle returning more than one peer id */
static int tlshd_genl_put_session_peerid(struct nl_msg *msg,
					 struct tlshd_handshake_parms *parms)
{
	int err;

	if (parms->session_peerid == TLS_NO_PEERID)
		return 0;

	err = nla_put_u32(msg, HANDSHAKE_A_DONE_REMOTE_PEERID,
			  parms->session_peerid);
	if (err < 0) {
		tlshd_log_nl_error("nla_put peer id", err);
		return -EIO;
	}

	return 0;
}

/**
 * tlshd_genl_done - Indicate anon handshake has completed successfully
 * @parms: buffer filled in with parameters
 *
 */
void tlshd_genl_done(struct tlshd_handshake_parms *parms)
{
	struct nlmsghdr *hdr;
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

	err = nla_put_u32(msg, HANDSHAKE_A_DONE_SOCKFD, parms->sockfd);
	if (err < 0) {
		tlshd_log_nl_error("nla_put sockfd", err);
		goto out_free;
	}
	if (parms->session_status)
		goto sendit;

	err = tlshd_genl_put_session_peerid(msg, parms);
	if (err < 0)
		goto out_free;

sendit:
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
