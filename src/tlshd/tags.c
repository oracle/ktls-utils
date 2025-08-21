/**
 * @file tags.c
 * @brief TLS session tagging
 *
 * @copyright
 * Copyright (c) 2025 Oracle and/or its affiliates.
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
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>

#include "tlshd.h"

struct tlshd_tags_filter;

/**
 * @struct tlshd_tags_filter_type
 * @brief In-memory tag filter type
 *
 * @ft_name:		Filter type name using dotted notation
 * @ft_validate:	Validates filter configuration at parse time
 * @ft_match:		Matches filter against a session's peer certificate
 */
struct tlshd_tags_filter_type {
	const gchar			*ft_name;
	bool				(*ft_validate)(struct tlshd_tags_filter *filter);
	bool				(*ft_match)(struct tlshd_tags_filter *filter,
						    gnutls_session_t session);
};

/**
 * @var tlshd_tags_filter_type_hash
 * @brief Hash table of all tag filter types
 */
static GHashTable *tlshd_tags_filter_type_hash;

/** @name tagsFilterTypes
 *
 * Add tag filter types to a hash table for fast lookup by type name.
 */

///@{

/**
 * @var tlshd_tags_static_filter_types
 * @brief Fixed, internally-defined tag filter types
 */
static const struct tlshd_tags_filter_type tlshd_tags_static_filter_types[] = {

	/* Certificate fields, RFC 5280, Section 4.1.1 */

	{
		/* RFC 5280, Section 4.1.1.2 */
		.ft_name		= "x509.cert.signatureAlgorithm",
	},

	/* To-Be-Signed fields, RFC 5280, Section 4.1.2 */

	{
		/* RFC 5280, Section 4.1.2.1 */
		.ft_name		= "x509.tbs.version",
	},
	{
		/* RFC 5280, Section 4.1.2.2 */
		.ft_name		= "x509.tbs.serialNumber",
	},
	{
		/* RFC 5280, Section 4.1.2.3 */
		.ft_name		= "x509.tbs.signature",
	},
	{
		/* RFC 5280, Section 4.1.2.4 */
		.ft_name		= "x509.tbs.issuer",
	},
	{
		/* RFC 5280, Section 4.1.2.5 */
		.ft_name		= "x509.tbs.validity.notBefore",
	},
	{
		/* RFC 5280, Section 4.1.2.5 */
		.ft_name		= "x509.tbs.validity.notAfter",
	},
	{
		/* RFC 5280, Section 4.1.2.6 */
		.ft_name		= "x509.tbs.subject",
	},

	/* Standard certificate extensions, RFC 5280, Section 4.2.1 */

	{
		/* RFC 5280, Section 4.2.1.3 */
		.ft_name		= "x509.extension.keyUsage",
	},
	{
		/* RFC 5280, Section 4.2.1.12 */
		.ft_name		= "x509.extension.extendedKeyUsage",
	},

	/* Derived fields */

	{
		/* Locally implemented */
		.ft_name		= "x509.derived.fingerprint",
	},
	{
		/* Locally implemented */
		.ft_name		= "x509.derived.selfSigned",
	},
};

/**
 * @brief Free the "filter type" hash table
 */
static void tlshd_tags_filter_type_hash_destroy(void)
{
	if (!tlshd_tags_filter_type_hash)
		return;

	g_hash_table_destroy(tlshd_tags_filter_type_hash);
	tlshd_tags_filter_type_hash = NULL;
}

/**
 * @brief Initialize the "filter type" hash table
 *
 * @retval true   Filter type hash initialization succeeded
 * @retval false  Filter type hash initialization failed
 */
static bool tlshd_tags_filter_type_hash_init(void)
{
	size_t i;

	tlshd_tags_filter_type_hash = g_hash_table_new(g_str_hash, g_str_equal);
	if (!tlshd_tags_filter_type_hash) {
		tlshd_log_error("Failed to allocate 'filter type' hash table\n");
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(tlshd_tags_static_filter_types); ++i) {
		const struct tlshd_tags_filter_type *filter_type;

		filter_type = &tlshd_tags_static_filter_types[i];
		g_hash_table_insert(tlshd_tags_filter_type_hash,
				    (gpointer)filter_type->ft_name,
				    (gpointer)filter_type);
	}
	return true;
}

///@}

/** @name tagsInit
 *
 *  Subsystem start-up / shutdown APIs
 */

///@{

/**
 * @brief Initialize the TLS session tag subsystem
 * @param[in]      tagsdir pathname of directory containing files that define tags
 *
 * @retval true   Subsystem initialization succeeded
 * @retval false  Subsystem initialization failed
 */
bool tlshd_tags_config_init(__attribute__ ((unused)) const char *tagsdir)
{
	return tlshd_tags_filter_type_hash_init();
}

/**
 * @brief Release all session tag-related resources
 *
 */
void tlshd_tags_config_shutdown(void)
{
	tlshd_tags_filter_type_hash_destroy();
}

/**
 * @brief Reload the TLS session tag subsystem
 * @param[in]      tagsdir pathname of directory containing files that define tags
 *
 * Atomically reloads the tags configuration. If loading the new
 * configuration fails, the existing configuration remains in effect.
 *
 * @retval true   Subsystem reload succeeded
 * @retval false  Subsystem reload failed, existing configuration retained
 */
bool tlshd_tags_config_reload(__attribute__ ((unused)) const char *tagsdir)
{
	return true;
}

///@}
