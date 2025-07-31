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
	return true;
}

/**
 * @brief Release all session tag-related resources
 *
 */
void tlshd_tags_config_shutdown(void)
{
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
