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

//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/stat.h>
//#include <sys/syscall.h>

#include <stdbool.h>
//#include <unistd.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <fcntl.h>
//#include <errno.h>
//#include <string.h>
//#include <libgen.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
//#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <glib.h>
//#include <glib-2.0/glib/gregex.h>
#include <yaml.h>

#include "tlshd.h"

/* --- Filter & tag name validation --- */

static const gchar *tlshd_tags_name_valid = "[a-zA-Z0-9_\\-]+";
static GRegex *tlshd_tags_name_regex;

static void tlshd_tags_name_destroy(void)
{
	if (tlshd_tags_name_regex)
		g_regex_unref(tlshd_tags_name_regex);
}

static bool tlshd_tags_name_init(void)
{
	GError *error;

	error = NULL;
	tlshd_tags_name_regex = g_regex_new(tlshd_tags_name_valid, 0,
					    G_REGEX_MATCH_ANCHORED, &error);
	if (tlshd_tags_name_regex == NULL) {
		tlshd_log_gerror("Failed to compile name regex", error);
		g_error_free(error);
		return false;
	}
	return true;
}

static bool tlshd_tags_name_is_valid(const gchar *name)
{
	g_autoptr(GMatchInfo) match_info = NULL;
	int namelen = strlen(name);
	int start_pos, end_pos;
	bool res;

	if (namelen < 1) {
		tlshd_log_error("Object name is too short\n");
		return false;
	}

	res = g_regex_match(tlshd_tags_name_regex, name,
			    G_REGEX_MATCH_ANCHORED, &match_info);
	if (!res)
		goto invalid;
	g_match_info_fetch_pos(match_info, 0, &start_pos, &end_pos);
	if (start_pos != 0 || end_pos != namelen)
		goto invalid;
	return true;

invalid:
	tlshd_log_debug("Name '%s' contains invalid characters", name);
	return false;
}

/* --- libyaml helpers --- */

/* This depends on the yaml_event_type_t enum being densely packed */
static const char *show_yaml_event_type(const yaml_event_t *event)
{
	static const char *labels[] = {
		[YAML_NO_EVENT]			= "YAML_NO_EVENT",
		[YAML_STREAM_START_EVENT]	= "YAML_STREAM_START_EVENT",
		[YAML_STREAM_END_EVENT]		= "YAML_STREAM_END_EVENT",
		[YAML_DOCUMENT_START_EVENT]	= "YAML_DOCUMENT_START_EVENT",
		[YAML_DOCUMENT_END_EVENT]	= "YAML_DOCUMENT_END_EVENT",
		[YAML_ALIAS_EVENT]		= "YAML_ALIAS_EVENT",
		[YAML_SCALAR_EVENT]		= "YAML_SCALAR_EVENT",
		[YAML_SEQUENCE_START_EVENT]	= "YAML_SEQUENCE_START_EVENT",
		[YAML_SEQUENCE_END_EVENT]	= "YAML_SEQUENCE_END_EVENT",
		[YAML_MAPPING_START_EVENT]	= "YAML_MAPPING_START_EVENT",
		[YAML_MAPPING_END_EVENT]	= "YAML_MAPPING_END_EVENT",
	};

	if (event->type > YAML_MAPPING_END_EVENT)
		return "invalid YAML event";
	return labels[event->type];
}

/* --- Tag configuration file parsing --- */

enum tlshd_tags_fsm_state_index {
	PS_STOP,
	PS_START,
	PS_STREAM,
	PS_DOCUMENT,
	PS_TOP_LEVEL,

	PS_FILTERS,
	PS_FILTER,
	PS_FILTER_KEYS,
	PS_FILTER_KEY,
	PS_FILTER_TYPE_VALUE,
	PS_FILTER_PATTERN_VALUE,
	PS_FILTER_PURPOSE_LIST,
	PS_FILTER_KEY_USAGE,

	PS_TAGS,
	PS_TAG,
	PS_TAG_KEYS,
	PS_TAG_KEY,
	PS_TAG_VALUE_FILTER,
	PS_TAG_VALUE_FILTER_LIST,

	PS_UNEXPECTED_INPUT_TOKEN,
	PS_FAILURE,
};

struct tlshd_tags_filter;

struct tlshd_tags_filter_type {
	gchar				*ft_name;
	bool				(*ft_validate)(struct tlshd_tags_filter *filter);
	bool				(*ft_match)(struct tlshd_tags_filter *filter,
						    gnutls_session_t session);
};

static GHashTable *tlshd_tags_filter_type_hash;

struct tlshd_tags_filter {
	gchar				*fi_name;
	struct tlshd_tags_filter_type	*fi_filter_type;

	/* filter arguments */
	gchar				*fi_pattern;
	GPatternSpec			*fi_pattern_spec;
	unsigned int			fi_purpose_mask;
	time_t				fi_time;
};

static GHashTable *tlshd_tags_filter_hash;

struct tlshd_tags_tag {
	gchar				*ta_name;
	GPtrArray			*ta_noninverted_filters;
	GPtrArray			*ta_inverted_filters;

	bool				ta_matched;
};

static GHashTable *tlshd_tags_tag_hash;

struct tlshd_tags_parser_state {
	yaml_event_t			ps_yaml_event;

	enum tlshd_tags_fsm_state_index	ps_fsm_state;

	struct tlshd_tags_filter	*ps_current_filter;
	struct tlshd_tags_tag		*ps_current_tag;
};

static enum tlshd_tags_fsm_state_index
tlshd_tags_top_level(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *mapping = (const char *)event->data.scalar.value;

	if (strcmp(mapping, "filters") == 0)
		return PS_FILTERS;
	else if (strcmp(mapping, "tags") == 0)
		return PS_TAGS;

	tlshd_log_error("Unexpected mapping name: %s\n", mapping);
	return PS_UNEXPECTED_INPUT_TOKEN;
}

/* --- Filters --- */

static void tlshd_tags_filter_free(struct tlshd_tags_filter *filter)
{
	if (!filter)
		return;

	if (tlshd_debug > 3)
		tlshd_log_debug("Removing filter '%s' from the filter hash",
				filter->fi_name);

	if (filter->fi_pattern_spec)
		g_pattern_spec_free(filter->fi_pattern_spec);
	g_free(filter->fi_pattern);
	g_free(filter->fi_name);
	g_free(filter);
}

static void tlshd_tags_filter_hash_destroy(void)
{
	GHashTableIter iter;
	gpointer key, value;

	if (!tlshd_tags_filter_hash)
		return;

	g_hash_table_iter_init(&iter, tlshd_tags_filter_hash);
	while (g_hash_table_iter_next(&iter, &key, &value))
		tlshd_tags_filter_free((struct tlshd_tags_filter *)value);

	g_hash_table_destroy(tlshd_tags_filter_hash);
	tlshd_tags_filter_hash = NULL;
}

static bool
tlshd_tags_filter_hash_init(void)
{
	tlshd_tags_filter_hash = g_hash_table_new(g_str_hash, g_str_equal);
	return tlshd_tags_filter_hash != NULL;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_create(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	gchar *value = (gchar *)event->data.scalar.value;
	struct tlshd_tags_filter *filter;

	if (!tlshd_tags_name_is_valid(value))
		return PS_FAILURE;

	filter = g_malloc0(sizeof(*filter));
	if (!filter) {
		tlshd_log_error("Failed to allocate new filter\n");
		return PS_FAILURE;
	}

	filter->fi_name = g_strdup((const char *)value);
	if (!filter->fi_name) {
		g_free(filter);
		tlshd_log_error("Failed to allocate new filter\n");
		return PS_FAILURE;
	}

	current->ps_current_filter = filter;
	return PS_FILTER_KEYS;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_type_add(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *name = (const char *)event->data.scalar.value;

	if (!current->ps_current_filter) {
		tlshd_log_error("No current filter\n");
		return PS_FAILURE;
	}

	if (current->ps_current_filter->fi_filter_type) {
		tlshd_log_error("Filter type already set for filter '%s'\n",
				name);
		return PS_FAILURE;
	}

	gconstpointer key = (gconstpointer)name;
	gpointer filter_type;

	filter_type = g_hash_table_lookup(tlshd_tags_filter_type_hash, key);
	if (!filter_type) {
		tlshd_log_debug("Filter type '%s' is not supported", name);
		return PS_UNEXPECTED_INPUT_TOKEN;
	}

	current->ps_current_filter->fi_filter_type = filter_type;
	return PS_FILTER_KEY;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_key_set(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *key = (const char *)event->data.scalar.value;

	if (strcmp(key, "type") == 0)
		return PS_FILTER_TYPE_VALUE;
	else if (strcmp(key, "pattern") == 0)
		return PS_FILTER_PATTERN_VALUE;
	else if (strcmp(key, "purpose") == 0)
		return PS_FILTER_PURPOSE_LIST;

	tlshd_log_error("Unexpected token: %s\n", key);
	return PS_UNEXPECTED_INPUT_TOKEN;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_pattern_set(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *pattern = (const char *)event->data.scalar.value;

	if (!current->ps_current_filter) {
		tlshd_log_error("No current filter\n");
		return PS_FAILURE;
	}

	current->ps_current_filter->fi_pattern = g_strdup(pattern);
	if (!current->ps_current_filter->fi_pattern) {
		tlshd_log_error("Failed to allocate filter pattern\n");
		return PS_FAILURE;
	}

	return PS_FILTER_KEY;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_key_usage_set(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *name = (const char *)event->data.scalar.value;
	unsigned int key_usage = 0;

	if (strcmp(name, "digitalSignature") == 0)
		key_usage = GNUTLS_KEY_DIGITAL_SIGNATURE;
	else if (strcmp(name, "nonRepudiation") == 0)
		key_usage = GNUTLS_KEY_NON_REPUDIATION;
	else if (strcmp(name, "keyEncipherment") == 0)
		key_usage = GNUTLS_KEY_KEY_ENCIPHERMENT;
	else if (strcmp(name, "dataEncipherment") == 0)
		key_usage = GNUTLS_KEY_DATA_ENCIPHERMENT;
	else if (strcmp(name, "keyAgreement") == 0)
		key_usage = GNUTLS_KEY_KEY_AGREEMENT;
	else if (strcmp(name, "keyCertSign") == 0)
		key_usage = GNUTLS_KEY_KEY_CERT_SIGN;
	else if (strcmp(name, "cRLSign") == 0)
		key_usage = GNUTLS_KEY_CRL_SIGN;
	else if (strcmp(name, "encipherOnly") == 0)
		key_usage = GNUTLS_KEY_ENCIPHER_ONLY;
	else if (strcmp(name, "decipherOnly") == 0)
		key_usage = GNUTLS_KEY_DECIPHER_ONLY;
	else {
		tlshd_log_error("Unrecognized key usage: %s\n", name);
		return PS_UNEXPECTED_INPUT_TOKEN;
	}

	current->ps_current_filter->fi_purpose_mask |= key_usage;
	return PS_FILTER_KEY_USAGE;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_validate(struct tlshd_tags_parser_state *current)
{
	struct tlshd_tags_filter *filter = current->ps_current_filter;

	if (!filter) {
		tlshd_log_error("No current filter\n");
		return PS_FAILURE;
	}

	if (!filter->fi_filter_type->ft_validate) {
		tlshd_log_error("Filter '%s' filter type is not yet implemented.",
				filter->fi_name);
		return PS_FILTER;
	}
	if (!filter->fi_filter_type->ft_validate(filter))
		return PS_FAILURE;

	if (tlshd_debug > 3)
		tlshd_log_debug("Adding filter '%s' to the filter hash",
				filter->fi_name);
	g_hash_table_insert(tlshd_tags_filter_hash, filter->fi_name,
			    (gpointer)filter);
	current->ps_current_filter = NULL;
	return PS_FILTER;
}

/* --- Tags --- */

static void tlshd_tags_name_free_cb(gpointer data,
				    __attribute__ ((unused)) gpointer user_data)
{
	g_free(data);
}

static void tlshd_tags_tag_free(struct tlshd_tags_tag *tag)
{
	if (!tag)
		return;

	if (tlshd_debug > 3)
		tlshd_log_debug("Removing tag '%s' from the tag hash",
				tag->ta_name);

	if (tag->ta_noninverted_filters)
		g_ptr_array_foreach(tag->ta_noninverted_filters,
				    tlshd_tags_name_free_cb,
				    NULL);
	g_ptr_array_free(tag->ta_noninverted_filters, TRUE);
	if (tag->ta_inverted_filters)
		g_ptr_array_foreach(tag->ta_inverted_filters,
				    tlshd_tags_name_free_cb,
				    NULL);
	g_ptr_array_free(tag->ta_inverted_filters, TRUE);

	g_free(tag->ta_name);
	g_free(tag);
}

static void tlshd_tags_tag_hash_destroy(void)
{
	GHashTableIter iter;
	gpointer key, value;

	if (!tlshd_tags_tag_hash)
		return;

	g_hash_table_iter_init(&iter, tlshd_tags_tag_hash);
	while (g_hash_table_iter_next(&iter, &key, &value))
		tlshd_tags_tag_free((struct tlshd_tags_tag *)value);

	g_hash_table_destroy(tlshd_tags_tag_hash);
	tlshd_tags_tag_hash = NULL;
}

static bool tlshd_tags_tag_hash_init(void)
{
	tlshd_tags_tag_hash = g_hash_table_new(g_str_hash, g_str_equal);
	return tlshd_tags_tag_hash != NULL;
}


static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_create(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	gchar *value = (gchar *)event->data.scalar.value;
	struct tlshd_tags_tag *tag;

	if (!tlshd_tags_name_is_valid(value))
		return PS_FAILURE;

	tag = g_malloc0(sizeof(*tag));
	if (!tag)
		goto err0;

	tag->ta_name = g_strdup((const gchar *)value);
	tag->ta_noninverted_filters = g_ptr_array_new();
	tag->ta_inverted_filters = g_ptr_array_new();
	if (!tag->ta_name || !tag->ta_noninverted_filters || !tag->ta_inverted_filters)
		goto free;

	current->ps_current_tag = tag;
	return PS_TAG_KEYS;

free:
	tlshd_tags_tag_free(tag);
err0:
	tlshd_log_error("Failed to allocate new tag\n");
	return PS_FAILURE;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_key_set(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *key = (const char *)event->data.scalar.value;

	if (strcmp(key, "filter") == 0)
		return PS_TAG_VALUE_FILTER;

	tlshd_log_error("Unexpected tag attribute: %s\n", key);
	return PS_UNEXPECTED_INPUT_TOKEN;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_filter_add(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	gchar *value = (gchar *)event->data.scalar.value;
	GPtrArray *filters;
	gchar *filter_name;

	if (!current->ps_current_tag) {
		tlshd_log_error("No current tag\n");
		return PS_FAILURE;
	}

	if (g_str_has_prefix(value, "not ")) {
		filters = current->ps_current_tag->ta_inverted_filters;
		value += 4;
	} else {
		filters = current->ps_current_tag->ta_noninverted_filters;
	}

	if (!tlshd_tags_name_is_valid(value))
		return PS_FAILURE;

	filter_name = g_strdup((const gchar *)value);
	if (!filter_name) {
		tlshd_log_error("Failed to allocate filter name\n");
		return PS_FAILURE;
	}

	tlshd_log_debug("Adding filter: '%s' to tag '%s'", (const char *)value,
			current->ps_current_tag->ta_name);
	g_ptr_array_add(filters, filter_name);
	return PS_TAG_VALUE_FILTER_LIST;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_validate(struct tlshd_tags_parser_state *current)
{
	struct tlshd_tags_tag *tag = current->ps_current_tag;

	if (!tag) {
		tlshd_log_error("No current tag\n");
		return PS_FAILURE;
	}

	if (tlshd_debug > 3)
		tlshd_log_debug("Adding tag '%s' to the tag hash",
				tag->ta_name);

	g_hash_table_insert(tlshd_tags_tag_hash, tag->ta_name,
			    (gpointer)tag);
	current->ps_current_tag = NULL;
	return PS_TAG;
}

/* --- FSM states --- */

typedef enum tlshd_tags_fsm_state_index
	(*tlshd_tags_action_fn)(struct tlshd_tags_parser_state *current);

struct tlshd_tags_fsm_transition {
	yaml_event_type_t		pt_yaml_event;
	enum tlshd_tags_fsm_state_index	pt_next_state;
	tlshd_tags_action_fn		pt_action;
};

#define NEXT_STATE(event, state) \
	{ \
		.pt_yaml_event		= event, \
		.pt_next_state		= state, \
	}

#define NEXT_ACTION(event, action) \
	{ \
		.pt_yaml_event		= event, \
		.pt_action		= action, \
	}

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_start[] = {
	NEXT_STATE(YAML_STREAM_START_EVENT, PS_STREAM),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_stream[] = {
	NEXT_STATE(YAML_DOCUMENT_START_EVENT, PS_DOCUMENT),
	NEXT_STATE(YAML_STREAM_END_EVENT, PS_STOP),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_document[] = {
	NEXT_STATE(YAML_MAPPING_START_EVENT, PS_TOP_LEVEL),
	NEXT_STATE(YAML_DOCUMENT_END_EVENT, PS_STREAM),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_top_level[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_top_level),
	NEXT_STATE(YAML_MAPPING_END_EVENT, PS_DOCUMENT),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filters[] = {
	NEXT_STATE(YAML_MAPPING_START_EVENT, PS_FILTER),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_filter_create),
	NEXT_STATE(YAML_MAPPING_END_EVENT, PS_TOP_LEVEL),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter_keys[] = {
	NEXT_STATE(YAML_MAPPING_START_EVENT, PS_FILTER_KEY),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter_key[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_filter_key_set),
	NEXT_ACTION(YAML_MAPPING_END_EVENT, tlshd_tags_filter_validate),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter_type_value[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_filter_type_add),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter_pattern_value[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_filter_pattern_set),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter_purpose_list[] = {
	NEXT_STATE(YAML_SEQUENCE_START_EVENT, PS_FILTER_KEY_USAGE),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_filter_key_usage[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_filter_key_usage_set),
	NEXT_STATE(YAML_SEQUENCE_END_EVENT, PS_FILTER_KEY),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_tags[] = {
	NEXT_STATE(YAML_MAPPING_START_EVENT, PS_TAG),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_tag[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_tag_create),
	NEXT_STATE(YAML_MAPPING_END_EVENT, PS_TOP_LEVEL),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_tag_keys[] = {
	NEXT_STATE(YAML_MAPPING_START_EVENT, PS_TAG_KEY),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_tag_key[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_tag_key_set),
	NEXT_ACTION(YAML_MAPPING_END_EVENT, tlshd_tags_tag_validate),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_tag_value_filter[] = {
	NEXT_STATE(YAML_SEQUENCE_START_EVENT, PS_TAG_VALUE_FILTER_LIST),
};

static const struct tlshd_tags_fsm_transition tlshd_tags_transitions_tag_value_filter_list[] = {
	NEXT_ACTION(YAML_SCALAR_EVENT, tlshd_tags_tag_filter_add),
	NEXT_STATE(YAML_SEQUENCE_END_EVENT, PS_TAG_KEY),
};

struct tlshd_tags_fsm_state {
	const char			*ts_name;
	const struct tlshd_tags_fsm_transition *ts_transitions;
	size_t				ts_transition_count;
};

#define FSM_STATE(name, array) \
	[name] = { \
		.ts_name		= #name, \
		.ts_transitions		= array, \
		.ts_transition_count	= ARRAY_SIZE(array), \
	}

#define TERMINAL_STATE(name) \
	[name] = { \
		.ts_name		= #name, \
		.ts_transition_count	= 0, \
	}

static const struct tlshd_tags_fsm_state tlshd_tags_fsm_state_table[] = {
	TERMINAL_STATE(PS_STOP),
	FSM_STATE(PS_START, tlshd_tags_transitions_start),
	FSM_STATE(PS_STREAM, tlshd_tags_transitions_stream),
	FSM_STATE(PS_DOCUMENT, tlshd_tags_transitions_document),
	FSM_STATE(PS_TOP_LEVEL, tlshd_tags_transitions_top_level),
	FSM_STATE(PS_FILTERS, tlshd_tags_transitions_filters),
	FSM_STATE(PS_FILTER, tlshd_tags_transitions_filter),
	FSM_STATE(PS_FILTER_KEYS, tlshd_tags_transitions_filter_keys),
	FSM_STATE(PS_FILTER_KEY, tlshd_tags_transitions_filter_key),
	FSM_STATE(PS_FILTER_TYPE_VALUE, tlshd_tags_transitions_filter_type_value),
	FSM_STATE(PS_FILTER_PATTERN_VALUE, tlshd_tags_transitions_filter_pattern_value),
	FSM_STATE(PS_FILTER_PURPOSE_LIST, tlshd_tags_transitions_filter_purpose_list),
	FSM_STATE(PS_FILTER_KEY_USAGE, tlshd_tags_transitions_filter_key_usage),
	FSM_STATE(PS_TAGS, tlshd_tags_transitions_tags),
	FSM_STATE(PS_TAG, tlshd_tags_transitions_tag),
	FSM_STATE(PS_TAG_KEYS, tlshd_tags_transitions_tag_keys),
	FSM_STATE(PS_TAG_KEY, tlshd_tags_transitions_tag_key),
	FSM_STATE(PS_TAG_VALUE_FILTER, tlshd_tags_transitions_tag_value_filter),
	FSM_STATE(PS_TAG_VALUE_FILTER_LIST, tlshd_tags_transitions_tag_value_filter_list),
	TERMINAL_STATE(PS_UNEXPECTED_INPUT_TOKEN),
	TERMINAL_STATE(PS_FAILURE),
};

/*
 * Each libyaml event produces zero or one input tokens.
 *
 * tlshd_tags_process_yaml_event() evaluates the event token based on
 * the current parser state, then advances to the next FSM state.
 */
static void
tlshd_tags_process_yaml_event(struct tlshd_tags_parser_state *current)
{
	const struct tlshd_tags_fsm_state *fsm_state =
		&tlshd_tags_fsm_state_table[current->ps_fsm_state];
	const yaml_event_t *event = &current->ps_yaml_event;
	const struct tlshd_tags_fsm_transition *transition;
	size_t i;

	if (fsm_state->ts_transition_count == 0)
		return;

	transition = NULL;
	for (i = 0; i < fsm_state->ts_transition_count; ++i) {
		if (fsm_state->ts_transitions[i].pt_yaml_event == event->type) {
			transition = &fsm_state->ts_transitions[i];
			break;
		}
	}
	if (transition == NULL) {
		tlshd_log_debug("ps_state=%s, unexpected event: %s\n",
			fsm_state->ts_name,
			show_yaml_event_type(event));
		current->ps_fsm_state = PS_FAILURE;
		return;
	}

	if (tlshd_debug > 3)
		tlshd_log_debug("ps_state=%s yaml event=%s",
			fsm_state->ts_name,
			show_yaml_event_type(event));

	if (transition->pt_action)
		current->ps_fsm_state = transition->pt_action(current);
	else
		current->ps_fsm_state = transition->pt_next_state;
}

static void tlshd_tags_parse_file(const char *filename)
{
	struct tlshd_tags_parser_state current;
	yaml_parser_t parser;
	FILE *fh;

	if (!yaml_parser_initialize(&parser)) {
		tlshd_log_error("Failed to initialize parser!\n");
		return;
	}

	fh = fopen(filename, "r");
	if (!fh) {
		tlshd_log_perror("fopen");
		yaml_parser_delete(&parser);
		return;
	}
	yaml_parser_set_input_file(&parser, fh);

	tlshd_log_debug("Parsing tags config file '%s'", filename);

	current.ps_fsm_state = PS_START;
	do {
		if (!yaml_parser_parse(&parser, &current.ps_yaml_event)) {
			tlshd_log_error("Parser error %d\n",
					parser.error);
			break;
		}
		tlshd_tags_process_yaml_event(&current);
		yaml_event_delete(&current.ps_yaml_event);

		if (current.ps_fsm_state == PS_FAILURE ||
		    current.ps_fsm_state == PS_UNEXPECTED_INPUT_TOKEN) {
			tlshd_log_error("Tag parsing failed, line: %zu column: %zu file: %s\n",
					parser.mark.line + 1,
					parser.mark.column,
					filename);
			break;
		}
	} while (current.ps_fsm_state != PS_STOP);

	yaml_parser_delete(&parser);
	fclose(fh);
}

static bool tlshd_tags_read_directory(const char *tagsdir)
{
	const gchar *filename;
	GError *error;
	GDir *dir;

	error = NULL;
	dir = g_dir_open(tagsdir, 0, &error);
	if (!dir) {
		tlshd_log_gerror("Failed to open the tags directory", error);
		g_error_free(error);
		return false;
	}

	while ((filename = g_dir_read_name(dir)) != NULL) {
		gchar *pathname;

		if (!g_str_has_suffix(filename, ".yml") &&
		    !g_str_has_suffix(filename, ".yaml"))
			continue;
		pathname = g_build_filename(tagsdir, filename, NULL);

		tlshd_tags_parse_file(pathname);
		g_free(pathname);
	}

	g_dir_close(dir);
	return true;
}

/* --- Filter Types --- */

static bool
tlshd_tags_filter_type_no_parameters(__attribute__ ((unused)) struct tlshd_tags_filter *filter)
{
	return true;
}

static bool
tlshd_tags_filter_type_validate_pattern(struct tlshd_tags_filter *filter)
{
	if (!filter->fi_pattern) {
		tlshd_log_error("Filter '%s' is missing a pattern.",
				filter->fi_name);
		return false;
	}
	filter->fi_pattern_spec = g_pattern_spec_new(filter->fi_pattern);
	if (!filter->fi_pattern_spec) {
		tlshd_log_error("Filter '%s' failed to compile.",
				filter->fi_name);
		return false;
	}

	if (filter->fi_purpose_mask != 0)
		tlshd_log_error("Filter '%s' key usage purpose is extraneous.",
				filter->fi_name);
	return true;
}

static bool
tlshd_tags_filter_type_validate_purpose(struct tlshd_tags_filter *filter)
{
	if (filter->fi_purpose_mask == 0) {
		tlshd_log_error("Filter '%s' is missing a key usage purpose.",
				filter->fi_name);
		return false;
	}
	if (filter->fi_pattern)
		tlshd_log_error("Filter '%s' pattern is extraneous.",
				filter->fi_name);
	return true;
}

static bool
tlshd_tags_filter_type_validate_time(struct tlshd_tags_filter *filter)
{
	struct tm tm;
	char *ret;

	memset(&tm, 0, sizeof(tm));
	ret = strptime(filter->fi_pattern, "%Y-%m-%d %H:%M:%S", &tm);
	if (!ret) {
		tlshd_log_error("Failed to convert notbefore time.");
		return false;
	}
	filter->fi_time = mktime(&tm);

	if (filter->fi_purpose_mask != 0)
		tlshd_log_error("Filter '%s' key usage purpose is extraneous.",
				filter->fi_name);
	return true;
}

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
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
	},
	{
		/* RFC 5280, Section 4.1.2.3 */
		.ft_name		= "x509.tbs.signature",
	},
	{
		/* RFC 5280, Section 4.1.2.4 */
		.ft_name		= "x509.tbs.issuer",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
	},
	{
		/* RFC 5280, Section 4.1.2.5 */
		.ft_name		= "x509.tbs.validity.notBefore",
		.ft_validate		= tlshd_tags_filter_type_validate_time,
	},
	{
		/* RFC 5280, Section 4.1.2.5 */
		.ft_name		= "x509.tbs.validity.notAfter",
		.ft_validate		= tlshd_tags_filter_type_validate_time,
	},
	{
		/* RFC 5280, Section 4.1.2.6 */
		.ft_name		= "x509.tbs.subject",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
	},

	/* Standard certificate extensions, RFC 5280, Section 4.2.1 */

	{
		/* RFC 5280, Section 4.2.1.3 */
		.ft_name		= "x509.extension.keyUsage",
		.ft_validate		= tlshd_tags_filter_type_validate_purpose,
	},
	{
		/* RFC 5280, Secttion 4.2.1.12 */
		.ft_name		= "x509.extension.extendedKeyUsage",
	},

	/* Derived fields */

	{
		/* Locally implemented */
		.ft_name		= "x509.derived.fingerprint",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
	},
	{
		/* Locally implemented */
		.ft_name		= "x509.derived.selfSigned",
		.ft_validate		= tlshd_tags_filter_type_no_parameters,
	},
};

static void tlshd_tags_filter_type_hash_destroy(void)
{
	if (!tlshd_tags_filter_type_hash)
		return;

	g_hash_table_destroy(tlshd_tags_filter_type_hash);
	tlshd_tags_filter_type_hash = NULL;
}

/*
 * Add the internally-implemented filter types to a hash table for
 * fast lookup by name.
 */
static bool tlshd_tags_filter_type_hash_init(void)
{
	size_t i;

	tlshd_tags_filter_type_hash = g_hash_table_new(g_str_hash, g_str_equal);
	if (!tlshd_tags_filter_type_hash) {
		tlshd_log_error("Failed to allocate 'filter type' hash table\n");
		tlshd_tags_filter_type_hash = NULL;
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(tlshd_tags_static_filter_types); ++i) {
		const struct tlshd_tags_filter_type *filter_type;

		filter_type = &tlshd_tags_static_filter_types[i];
		g_hash_table_insert(tlshd_tags_filter_type_hash,
				    filter_type->ft_name,
				    (gpointer)filter_type);
	}
	return true;
}

/* --- Subsystem start-up / shutdown APIs --- */

/**
 * tlshd_tags_config_init - Initialize the TLS session tags configuration
 * @tagsdir: pathname of directory containing files that define tags
 *
 */
bool tlshd_tags_config_init(const char *tagsdir)
{
	if (!tlshd_tags_name_init())
		goto out;
	if (!tlshd_tags_filter_type_hash_init())
		goto name;
	if (!tlshd_tags_filter_hash_init())
		goto filter_type_hash;
	if (!tlshd_tags_tag_hash_init())
		goto filter_hash;

	if (!tlshd_tags_read_directory(tagsdir))
		goto tag_hash;

	return true;

tag_hash:
	tlshd_tags_tag_hash_destroy();
filter_hash:
	tlshd_tags_filter_hash_destroy();
filter_type_hash:
	tlshd_tags_filter_type_hash_destroy();
name:
	tlshd_tags_name_destroy();
out:
	return false;
}

/**
 * tlshd_tags_config_shutdown - Release all tag-related resources
 *
 */
void tlshd_tags_config_shutdown(void)
{
	tlshd_tags_tag_hash_destroy();
	tlshd_tags_filter_hash_destroy();
	tlshd_tags_filter_type_hash_destroy();
	tlshd_tags_name_destroy();
}
