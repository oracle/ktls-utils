/**
 * @file dane.h
 * @brief DANE server authentication for client-side handshakes
 *
 * @copyright
 * Copyright (c) 2026 Oracle and/or its affiliates.
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

#ifndef _TLSHD_DANE_H_
#define _TLSHD_DANE_H_

#include <stdbool.h>
#include <gnutls/gnutls.h>

/**
 * @enum tlshd_dane_mode
 * @brief DANE policy in effect for one handshake
 *
 * Selected per handshake. The config file supplies a default only for
 * consumers that name no policy of their own.
 */
enum tlshd_dane_mode {
	TLSHD_DANE_MODE_OFF = 0,	/**< DANE is not consulted */
	TLSHD_DANE_MODE_OPPORTUNISTIC,	/**< DANE governs when it applies */
	TLSHD_DANE_MODE_REQUIRE,	/**< DANE must govern, or fail */
};

/**
 * @enum tlshd_dane_outcome
 * @brief Classification of one TLSA evaluation
 *
 * "Usable" is relative to the certificate usages, selectors, matching
 * types, and digest algorithms this implementation enables. This round
 * enables DANE-EE(3) only.
 */
enum tlshd_dane_outcome {
	/** Validated RRset with at least one usable record */
	TLSHD_DANE_SECURE_USABLE = 0,
	/** Validated RRset, no usable record; TLS must still authenticate */
	TLSHD_DANE_SECURE_UNUSABLE,
	/** DNSSEC-validated denial at every candidate base domain */
	TLSHD_DANE_SECURE_ABSENT,
	/** Provably unsigned span; DANE does not apply */
	TLSHD_DANE_INSECURE,
	/** Bogus, indeterminate, or failed lookup; never authorizes fallback */
	TLSHD_DANE_ERROR,
	/** DANE is inapplicable to this handshake; no lookup was made */
	TLSHD_DANE_NOT_APPLICABLE,
};

struct tlshd_dane_result;
struct tlshd_handshake_parms;

#ifdef HAVE_DANE

extern bool tlshd_dane_evaluate(struct tlshd_handshake_parms *parms);
extern const char *tlshd_dane_sni_name(const struct tlshd_handshake_parms *parms);
extern int tlshd_dane_verify(struct tlshd_handshake_parms *parms,
			     gnutls_session_t session);
extern void tlshd_dane_record_pkix(struct tlshd_handshake_parms *parms,
				   bool authenticated);
extern void tlshd_dane_record_unauth(struct tlshd_handshake_parms *parms);
extern void tlshd_dane_record_resumed(struct tlshd_handshake_parms *parms);
extern void tlshd_dane_audit(struct tlshd_handshake_parms *parms);
extern void tlshd_dane_release(struct tlshd_handshake_parms *parms);

#else	/* !HAVE_DANE */

static inline bool
tlshd_dane_evaluate(__attribute__ ((unused)) struct tlshd_handshake_parms *parms)
{
	return true;
}

static inline int
tlshd_dane_verify(__attribute__ ((unused)) struct tlshd_handshake_parms *parms,
		  __attribute__ ((unused)) gnutls_session_t session)
{
	return 0;
}

static inline void
tlshd_dane_record_pkix(__attribute__ ((unused)) struct tlshd_handshake_parms *parms,
		       __attribute__ ((unused)) bool authenticated)
{
}

static inline void
tlshd_dane_record_unauth(__attribute__ ((unused)) struct tlshd_handshake_parms *parms)
{
}

static inline void
tlshd_dane_record_resumed(__attribute__ ((unused)) struct tlshd_handshake_parms *parms)
{
}

static inline void
tlshd_dane_audit(__attribute__ ((unused)) struct tlshd_handshake_parms *parms)
{
}

static inline void
tlshd_dane_release(__attribute__ ((unused)) struct tlshd_handshake_parms *parms)
{
}

#endif	/* HAVE_DANE */

#endif	/* _TLSHD_DANE_H_ */
