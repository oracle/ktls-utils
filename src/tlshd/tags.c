/*
 * TLS session tagging
 *
 * Copyright (c) 2025 Oracle and/or its affiliates.
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
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>

#include "tlshd.h"

/* --- Subsystem start-up / shutdown APIs --- */

/**
 * tlshd_tags_config_init - Initialize the TLS session tags configuration
 * @tagsdir: pathname of directory containing files that define tags
 *
 */
void tlshd_tags_config_init(__attribute__ ((unused)) const char *tagsdir)
{
}

/**
 * tlshd_tags_config_shutdown - Release all tag-related resources
 *
 */
void tlshd_tags_config_shutdown(void)
{
}
