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
//#define _XOPEN_SOURCE
#include <time.h>

#include <gnutls/gnutls.h>
//#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include <glib.h>
#include <yaml.h>

#include "tlshd.h"

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
	GPtrArray			*ta_filter_names;
	GPtrArray			*ta_filters;

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
	struct tlshd_tags_filter *filter;

	filter = g_malloc0(sizeof(*filter));
	if (!filter) {
		tlshd_log_error("Failed to allocate new filter\n");
		return PS_FAILURE;
	}

	filter->fi_name = g_strdup((const char *)event->data.scalar.value);
	if (!filter->fi_name) {
		free(filter);
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
tlshd_tags_filter_finalize(struct tlshd_tags_parser_state *current)
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
	free(data);
}

static void tlshd_tags_tag_free(struct tlshd_tags_tag *tag)
{
	if (!tag)
		return;

	if (tlshd_debug > 3)
		tlshd_log_debug("Removing tag '%s' from the tag hash",
				tag->ta_name);

	/* filter objects are freed separately */
	if (tag->ta_filters)
		g_ptr_array_free(tag->ta_filters, TRUE);

	if (tag->ta_filter_names)
		g_ptr_array_foreach(tag->ta_filter_names,
				    tlshd_tags_name_free_cb,
				    NULL);
	g_ptr_array_free(tag->ta_filter_names, TRUE);

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
	struct tlshd_tags_tag *tag;

	tag = g_malloc0(sizeof(*tag));
	if (!tag)
		goto err0;

	tag->ta_name = g_strdup((const gchar *)event->data.scalar.value);
	tag->ta_filter_names = g_ptr_array_new();
	tag->ta_filters = g_ptr_array_new();
	if (!tag->ta_name || !tag->ta_filter_names || !tag->ta_filters)
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
	const char *name;

	if (!current->ps_current_tag) {
		tlshd_log_error("No current tag\n");
		return PS_FAILURE;
	}

	name = strdup((const char *)event->data.scalar.value);
	if (!name) {
		tlshd_log_error("Failed to allocate filter name\n");
		return PS_FAILURE;
	}

	g_ptr_array_add(current->ps_current_tag->ta_filter_names,
			(gpointer)name);
	return PS_TAG_VALUE_FILTER_LIST;
}

static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_finalize(struct tlshd_tags_parser_state *current)
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
	NEXT_ACTION(YAML_MAPPING_END_EVENT, tlshd_tags_filter_finalize),
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
	NEXT_ACTION(YAML_MAPPING_END_EVENT, tlshd_tags_tag_finalize),
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

static void tlshd_tags_filter_name_find_cb(gpointer data, gpointer user_data)
{
	struct tlshd_tags_tag *tag = (struct tlshd_tags_tag *)user_data;
	gconstpointer key = (gconstpointer)data;
	gpointer filter;

	filter = g_hash_table_lookup(tlshd_tags_filter_hash, key);
	if (!filter) {
		tlshd_log_debug("Filter '%s' in tag '%s' not found",
				(const char *)key, tag->ta_name);
		return;
	}
	g_ptr_array_add(tag->ta_filters, filter);
}

/*
 * To make the tag YAML documents fully declarative, we have to wait
 * until the tag_hash and filter_hash hashes have been fully parsed
 * before matching up the filter names in the tags to struct filters
 * in the ta_filters arrays.
 */
static void tlshd_tags_config_finalize(void)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, tlshd_tags_tag_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct tlshd_tags_tag *tag = (struct tlshd_tags_tag *)value;

		g_ptr_array_foreach(tag->ta_filter_names,
				    tlshd_tags_filter_name_find_cb, (gpointer)tag);
	}
}

/* --- Filter Types --- */

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

	/* strftime(s, max, "%a %b %d %H:%M:%S UTC %Y", &t) == 0) */

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

static gchar *
tlshd_tags_raw_to_hex(const uint8_t *input, size_t input_size)
{
	size_t i, output_size = (input_size * 2) + 1;
	gchar *c, *output;

	output = g_malloc(output_size);
	if (!output)
		return NULL;

	c = output;
	for (i = 0; i < input_size; i++) {
		snprintf(c, output_size, "%.2x", input[i]);
		c += 2;
		output_size -= 2;
		if (output_size < 2)
			break;
	}
	*c = '\0';

	return output;
}

static bool
tlshd_tags_filter_type_match_x509_cert_signaturealgorithm(struct tlshd_tags_filter *filter,
							  gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	bool res = false;
	gchar *name;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	name = NULL;
	ret = gnutls_x509_crt_get_signature_algorithm(peercert);
	if (ret != GNUTLS_SIGN_UNKNOWN)
		name = g_strdup(gnutls_sign_get_name(ret));
	if (!name) {
		char oid[128];
		size_t oid_size = sizeof(oid);

		ret = gnutls_x509_crt_get_signature_oid(peercert, oid, &oid_size);
		if (ret != GNUTLS_E_SUCCESS) {
			tlshd_log_error("Unknown signature algorithm");
			goto deinit;
		}
		name = g_strdup(oid);
	}

#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	res = g_pattern_spec_match(filter->fi_pattern_spec,
				   strlen(name), name, NULL);
#else
	res = g_pattern_match(filter->fi_pattern_spec,
			      strlen(name), name, NULL);
#endif

	tlshd_log_debug("Filter '%s' %s algorithm '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			name);
	g_free(name);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_tbs_version(struct tlshd_tags_filter *filter,
					      gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	bool res = false;
	char version[16];
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	ret = gnutls_x509_crt_get_version(peercert);
	if (ret < 0) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	snprintf(version, sizeof(version), "%u", ret);
#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	res = g_pattern_spec_match(filter->fi_pattern_spec,
				   strlen(version), version, NULL);
#else
	res = g_pattern_match(filter->fi_pattern_spec,
			      strlen(version), version, NULL);
#endif

	tlshd_log_debug("Filter '%s' %s version '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			version);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_tbs_serial(struct tlshd_tags_filter *filter,
					     gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	uint8_t serial[128];
	size_t serial_size;
	bool res = false;
	gchar *hex;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	serial_size = sizeof(serial);
	ret = gnutls_x509_crt_get_serial(peercert, serial, &serial_size);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	hex = tlshd_tags_raw_to_hex(serial, serial_size);
	if (!hex) {
		tlshd_log_error("No memory\n");
		goto deinit;
	}
#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	res = g_pattern_spec_match(filter->fi_pattern_spec,
				   strlen(hex), hex, NULL);
#else
	res = g_pattern_match(filter->fi_pattern_spec,
			      strlen(hex), hex, NULL);
#endif

	tlshd_log_debug("Filter '%s' %s serial '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			hex);
	g_free(hex);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_tbs_issuer(struct tlshd_tags_filter *filter,
					      gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	gnutls_datum_t dn;
	bool res = false;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	ret = gnutls_x509_crt_get_issuer_dn3(peercert, &dn, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	if (!g_pattern_spec_match(filter->fi_pattern_spec, dn.size,
			     (const gchar *)dn.data, NULL))
#else
	if (!g_pattern_match(filter->fi_pattern_spec, dn.size,
			     (const gchar *)dn.data, NULL))
#endif
		goto free;
	res = true;

free:
	tlshd_log_debug("Filter '%s' %s issuer '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			dn.data);
	gnutls_free(dn.data);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_tbs_validity_notbefore(struct tlshd_tags_filter *filter,
							 gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	time_t activation_time;
	bool res = false;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	activation_time = gnutls_x509_crt_get_activation_time(peercert);
	if (activation_time == (time_t)-1) {
		tlshd_log_error("Failed to retrieve activation time.");
		goto deinit;
	}

	res = (filter->fi_time >= activation_time);

	tlshd_log_debug("Filter '%s' %s validity.notBefore '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			filter->fi_pattern);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_tbs_validity_notafter(struct tlshd_tags_filter *filter,
							gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	time_t expiration_time;
	bool res = false;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	expiration_time = gnutls_x509_crt_get_expiration_time(peercert);
	if (expiration_time == (time_t)-1) {
		tlshd_log_error("Failed to retrieve expiration time.");
		goto deinit;
	}

	res = (filter->fi_time <= expiration_time);

	tlshd_log_debug("Filter '%s' %s validity.notBefore '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			filter->fi_pattern);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;

}

static bool
tlshd_tags_filter_type_match_x509_tbs_subject(struct tlshd_tags_filter *filter,
					      gnutls_session_t session)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	gnutls_datum_t dn;
	bool res = false;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	ret = gnutls_x509_crt_get_dn3(peercert, &dn, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	ret = g_pattern_spec_match(filter->fi_pattern_spec, dn.size,
				   (const gchar *)dn.data, NULL);
#else
	ret = g_pattern_match(filter->fi_pattern_spec, dn.size,
			      (const gchar *)dn.data, NULL);
#endif

	tlshd_log_debug("Filter '%s' %s subject '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			dn.data);
	gnutls_free(dn.data);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_extension_keyusage(struct tlshd_tags_filter *filter,
						      gnutls_session_t session)
{
	unsigned int key_usage, critical;
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	bool res = false;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	ret = gnutls_x509_crt_get_key_usage (peercert, &key_usage, &critical);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	res = (filter->fi_purpose_mask & key_usage) == filter->fi_purpose_mask;

	tlshd_log_debug("Filter '%s' %s key usage",
			filter->fi_name,
			res ? "matched" : "did not match");

deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static bool
tlshd_tags_filter_type_match_x509_derived_fingerprint(struct tlshd_tags_filter *filter,
						      gnutls_session_t session)
{
	bool sha1_res, sha256_res, res = false;
	const gnutls_datum_t *cert_list;
	uint8_t fingerprint[64];
	size_t size = sizeof(fingerprint);
	unsigned int num_certs = 0;
	gnutls_x509_crt_t peercert;
	gchar *hex;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		goto out;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		goto out;

	gnutls_x509_crt_init(&peercert);
	gnutls_x509_crt_import(peercert, &cert_list[0], GNUTLS_X509_FMT_DER);

	ret = gnutls_x509_crt_get_fingerprint(peercert, GNUTLS_DIG_SHA1,
					      fingerprint, &size);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	hex = tlshd_tags_raw_to_hex(fingerprint, size);
	if (!hex) {
		tlshd_log_error("No memory\n");
		goto deinit;
	}
#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	sha1_res = g_pattern_spec_match(filter->fi_pattern_spec,
					strlen(hex), hex, NULL);
#else
	sha1_res = g_pattern_match(filter->fi_pattern_spec,
				   strlen(hex), hex, NULL);
#endif
	g_free(hex);

	size = sizeof(fingerprint);
	ret = gnutls_x509_crt_get_fingerprint(peercert, GNUTLS_DIG_SHA256,
					      fingerprint, &size);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	hex = tlshd_tags_raw_to_hex(fingerprint, size);
	if (!hex) {
		tlshd_log_error("No memory\n");
		goto deinit;
	}
#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	sha256_res = g_pattern_spec_match(filter->fi_pattern_spec,
					  strlen(hex), hex, NULL);
#else
	sha256_res = g_pattern_match(filter->fi_pattern_spec,
				     strlen(hex), hex, NULL);
#endif
	g_free(hex);

	res = sha1_res | sha256_res;

	tlshd_log_debug("Filter '%s' %s fingerprint '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			filter->fi_pattern);
deinit:
	gnutls_x509_crt_deinit(peercert);
out:
	return res;
}

static const struct tlshd_tags_filter_type tlshd_tags_static_filter_types[] = {

	/* Certificate fields, RFC 5280, Section 4.1.1 */

	{
		/* RFC 5280, Section 4.1.1.2 */
		.ft_name		= "x509.cert.signatureAlgorithm",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
		.ft_match		= tlshd_tags_filter_type_match_x509_cert_signaturealgorithm,
	},

	/* To-Be-Signed fields, RFC 5280, Section 4.1.2 */

	{
		/* RFC 5280, Section 4.1.2.1 */
		.ft_name		= "x509.tbs.version",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
		.ft_match		= tlshd_tags_filter_type_match_x509_tbs_version,
	},
	{
		/* RFC 5280, Section 4.1.2.2 */
		.ft_name		= "x509.tbs.serialNumber",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
		.ft_match		= tlshd_tags_filter_type_match_x509_tbs_serial,
	},
	{
		/* RFC 5280, Section 4.1.2.3 */
		.ft_name		= "x509.tbs.signature",
		/* NYI */
	},
	{
		/* RFC 5280, Section 4.1.2.4 */
		.ft_name		= "x509.tbs.issuer",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
		.ft_match		= tlshd_tags_filter_type_match_x509_tbs_issuer,
	},
	{
		/* RFC 5280, Section 4.1.2.5 */
		.ft_name		= "x509.tbs.validity.notBefore",
		.ft_validate		= tlshd_tags_filter_type_validate_time,
		.ft_match		= tlshd_tags_filter_type_match_x509_tbs_validity_notbefore,
	},
	{
		/* RFC 5280, Section 4.1.2.5 */
		.ft_name		= "x509.tbs.validity.notAfter",
		.ft_validate		= tlshd_tags_filter_type_validate_time,
		.ft_match		= tlshd_tags_filter_type_match_x509_tbs_validity_notafter,
	},
	{
		/* RFC 5280, Section 4.1.2.6 */
		.ft_name		= "x509.tbs.subject",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
		.ft_match		= tlshd_tags_filter_type_match_x509_tbs_subject,
	},

	/* Standard certificate extensions, RFC 5280, Section 4.2.1 */

	{
		/* RFC 5280, Section 4.2.1.3 */
		.ft_name		= "x509.extension.keyUsage",
		.ft_validate		= tlshd_tags_filter_type_validate_purpose,
		.ft_match		= tlshd_tags_filter_type_match_x509_extension_keyusage,
	},
	{
		/* RFC 5280, Secttion 4.2.1.12 */
		.ft_name		= "x509.extension.extendedKeyUsage",
		/* NYI */
	},

	/* Derived fields */

	{
		/* Locally implemented */
		.ft_name		= "x509.derived.fingerprint",
		.ft_validate		= tlshd_tags_filter_type_validate_pattern,
		.ft_match		= tlshd_tags_filter_type_match_x509_derived_fingerprint,
	},
	{
		/* Locally implemented */
		.ft_name		= "x509.derived.selfSigned",
		/* NYI */
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

struct tlshd_tags_match_args {
	struct tlshd_tags_tag		*ma_tag;
	gnutls_session_t		ma_session;
	bool				ma_filter_matched;
};

static void tlshd_tags_x509_match_filters_cb(gpointer data, gpointer user_data)
{
	struct tlshd_tags_filter *filter = (struct tlshd_tags_filter *)data;
	struct tlshd_tags_match_args *args = (struct tlshd_tags_match_args *)user_data;

	/* A previous filter failed to match. No need to check any further. */
	if (!args->ma_filter_matched)
		return;

	if (!filter->fi_filter_type->ft_match) {
		args->ma_filter_matched = true;
		return;
	}
	args->ma_filter_matched = filter->fi_filter_type->ft_match(filter, args->ma_session);
}

/**
 * tlshd_tags_match_session - match certificate against configured tags
 * @session: session to assign tags to
 *
 * Side-effect: The ta_matched boolean is set in each tag in the
 * global tag list that is matched. When this function is called in
 * a child process, the parent process's tag list is not changed
 * (the parent's tag list is copied-on-write by fork(2)).
 */
void tlshd_tags_match_session(gnutls_session_t session)
{
	GHashTableIter iter;
	gpointer key, value;

	if (!tlshd_tags_tag_hash)
		return;

	g_hash_table_iter_init(&iter, tlshd_tags_tag_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct tlshd_tags_match_args args = {
			.ma_tag			= (struct tlshd_tags_tag *)value,
			.ma_session		= session,
			.ma_filter_matched	= true,
		};

		g_ptr_array_foreach(args.ma_tag->ta_filters,
				    tlshd_tags_x509_match_filters_cb, (gpointer)&args);
		args.ma_tag->ta_matched = args.ma_filter_matched;
	}
}

/* --- Subsystem start-up / shutdown APIs --- */

/**
 * tlshd_tags_config_init - Initialize the TLS session tags configuration
 * @tagsdir: pathname of directory containing files that define tags
 *
 */
void tlshd_tags_config_init(const char *tagsdir)
{
	if (!tlshd_tags_filter_type_hash_init())
		return;
	if (!tlshd_tags_filter_hash_init())
		goto filter_type_hash;
	if (!tlshd_tags_tag_hash_init())
		goto filter_hash;

	if (!tlshd_tags_read_directory(tagsdir))
		goto tag_hash;

	tlshd_tags_config_finalize();
	return;

tag_hash:
	tlshd_tags_tag_hash_destroy();
filter_hash:
	tlshd_tags_filter_hash_destroy();
filter_type_hash:
	tlshd_tags_filter_type_hash_destroy();
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
}
