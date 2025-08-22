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
#include <sys/stat.h>
#include <keyutils.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>
#include <yaml.h>

#include "tlshd.h"

/** @name tagsNameValidation
 *
 * Filter & tag name validation
 */

///@{

/**
 * @var tlshd_tags_name_valid
 * @brief Regular expression that defines a valid tag or filter name
 */
static const gchar *tlshd_tags_name_valid = "[a-zA-Z0-9_\\-]+";

/**
 * @var tlshd_tags_name_regex
 * @brief Compiled regular expression
 */
static GRegex *tlshd_tags_name_regex;

/**
 * @brief Free the compiled regular expression for verifying names
 */
static void tlshd_tags_name_destroy(void)
{
	if (tlshd_tags_name_regex)
		g_regex_unref(tlshd_tags_name_regex);
}

/**
 * @brief Initialize the compiled regular expression for verifying names
 *
 * @retval true   Regex initialization succeeded
 * @retval false  Regex initialization failed
 */
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

/**
 * @brief Predicate: is a tag or filter name valid?
 * @param[in]     name  NUL-terminated name to validate
 *
 * @retval true   "name" is a valid tag or filter name
 * @retval false  "name" is not a valid tag or filter name
 */
static bool tlshd_tags_name_is_valid(const gchar *name)
{
	g_autoptr(GMatchInfo) match_info = NULL;
	int namelen = strlen(name);
	int start_pos, end_pos;
	bool res;

	if (namelen < 1 || namelen > 255) {
		tlshd_log_error("Filter or tag name length %d outside valid range [1, 255]",
				namelen);
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

///@}

/** @name tagsLibYamlHelpers
 *
 * libyaml helpers
 */

///@{

/**
 * @brief Show a human-readable YAML event symbol
 * @param[in]     event  A YAML parser event
 *
 * This implementation depends on the yaml_event_type_t enum being
 * densely packed.
 *
 * @returns a constant NUL-terminated C string.
 */
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

	if (!event || event->type < 0 || event->type >= ARRAY_SIZE(labels))
		return "invalid YAML event";
	return labels[event->type];
}

///@}

/**
 * @enum tlshd_tags_fsm_state_index
 * YAML parser finite states
 */
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

	PS_UNEXPECTED_INPUT_TOKEN,
	PS_FAILURE,
};

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

/**
 * @struct tlshd_tags_filter
 * @brief In-memory tag filter
 */
struct tlshd_tags_filter {
	gchar				*fi_name;
	gchar				*fi_filename;
	struct tlshd_tags_filter_type	*fi_filter_type;

	/* filter arguments */
	gchar				*fi_pattern;
	GPatternSpec			*fi_pattern_spec;
	unsigned int			fi_purpose_mask;
	time_t				fi_time;
};

/**
 * @var tlshd_tags_filter_hash
 * @brief Hash table of all tag filters
 */
static GHashTable *tlshd_tags_filter_hash;

/**
 * @struct tlshd_tags_parser_state
 * @brief Global parser state
 */
struct tlshd_tags_parser_state {
	yaml_event_t			ps_yaml_event;

	enum tlshd_tags_fsm_state_index	ps_fsm_state;

	const char			*ps_current_filename;
	struct tlshd_tags_filter	*ps_current_filter;
};

static enum tlshd_tags_fsm_state_index
tlshd_tags_top_level(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *mapping;

	if (event->type != YAML_SCALAR_EVENT || !event->data.scalar.value) {
		tlshd_log_error("Unexpected event in top-level mapping");
		return PS_UNEXPECTED_INPUT_TOKEN;
	}

	mapping = (const char *)event->data.scalar.value;
	if (strcmp(mapping, "filters") == 0)
		return PS_FILTERS;

	tlshd_log_error("Unexpected mapping name: %s", mapping);
	return PS_UNEXPECTED_INPUT_TOKEN;
}

/** @name tagsFilters
 *
 * TLS session tag filters
 */

///@{

/**
 * @brief Free one tag filter
 * @param[in]     filter  Filter object to be freed
 */
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
	g_free(filter->fi_filename);
	g_free(filter->fi_name);
	g_free(filter);
}

/**
 * @brief Free the tag filter hash table
 */
static void tlshd_tags_filter_hash_destroy(void)
{
	if (!tlshd_tags_filter_hash)
		return;

	g_hash_table_destroy(tlshd_tags_filter_hash);
	tlshd_tags_filter_hash = NULL;
}

/**
 * @brief Initialize the tag filter hash table
 *
 * @retval true   Tag filter hash table initialization succeeded
 * @retval false  Tag filter hash table initialization failed
 */
static bool tlshd_tags_filter_hash_init(void)
{
	tlshd_tags_filter_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						       NULL,
						       (GDestroyNotify)tlshd_tags_filter_free);
	return tlshd_tags_filter_hash != NULL;
}

/**
 * @brief Create a new tag filter and make it the current filter
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
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
		tlshd_log_error("Failed to allocate new filter");
		return PS_FAILURE;
	}

	filter->fi_name = g_strdup((const char *)value);
	if (!filter->fi_name) {
		g_free(filter);
		tlshd_log_error("Failed to allocate new filter");
		return PS_FAILURE;
	}
	filter->fi_filename = g_strdup(current->ps_current_filename);
	if (!filter->fi_filename) {
		g_free(filter->fi_name);
		g_free(filter);
		tlshd_log_error("Failed to allocate new filter");
		return PS_FAILURE;
	}

	current->ps_current_filter = filter;
	return PS_FILTER_KEYS;
}

/**
 * @brief Start parsing a new filter specification
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_type_add(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *name = (const char *)event->data.scalar.value;
	gpointer filter_type;

	if (!current->ps_current_filter) {
		tlshd_log_error("No current filter");
		return PS_FAILURE;
	}

	if (current->ps_current_filter->fi_filter_type) {
		tlshd_log_error("Filter type already set for filter '%s'",
				name);
		return PS_FAILURE;
	}

	filter_type = g_hash_table_lookup(tlshd_tags_filter_type_hash,
					  (gconstpointer)name);
	if (!filter_type) {
		tlshd_log_debug("Filter type '%s' is not supported", name);
		return PS_UNEXPECTED_INPUT_TOKEN;
	}

	current->ps_current_filter->fi_filter_type = filter_type;
	return PS_FILTER_KEY;
}

/**
 * @brief Parse a filter type
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
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

	tlshd_log_error("Unexpected token: %s", key);
	return PS_UNEXPECTED_INPUT_TOKEN;
}

/**
 * @brief Parse a pattern-based filter-specification
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_pattern_set(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *pattern = (const char *)event->data.scalar.value;
	int wildcard_count = 0;
	const char *p;

	if (!current->ps_current_filter) {
		tlshd_log_error("No current filter");
		return PS_FAILURE;
	}

	for (p = pattern; *p; p++)
		if (*p == '*' || *p == '?')
			wildcard_count++;
	if (wildcard_count > 16) {
		tlshd_log_error("Pattern for filter '%s' contains too many wildcards (%d > 16)",
				current->ps_current_filter->fi_name,
				wildcard_count);
		return PS_FAILURE;
	}

	current->ps_current_filter->fi_pattern = g_strdup(pattern);
	if (!current->ps_current_filter->fi_pattern) {
		tlshd_log_error("Failed to allocate filter pattern");
		return PS_FAILURE;
	}

	current->ps_current_filter->fi_pattern_spec = g_pattern_spec_new(pattern);
	if (!current->ps_current_filter->fi_pattern_spec) {
		tlshd_log_error("Failed to compile filter pattern");
		g_free(current->ps_current_filter->fi_pattern);
		current->ps_current_filter->fi_pattern = NULL;
		return PS_FAILURE;
	}

	return PS_FILTER_KEY;
}

/**
 * @brief Parse a keyUsage filter specification
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
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
		tlshd_log_error("Unrecognized key usage: %s", name);
		return PS_UNEXPECTED_INPUT_TOKEN;
	}

	current->ps_current_filter->fi_purpose_mask |= key_usage;
	return PS_FILTER_KEY_USAGE;
}

/**
 * @brief Validate a filter and insert it into the filter hash table
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
static enum tlshd_tags_fsm_state_index
tlshd_tags_filter_validate(struct tlshd_tags_parser_state *current)
{
	struct tlshd_tags_filter *filter = current->ps_current_filter;

	if (!filter) {
		tlshd_log_error("No current filter");
		return PS_FAILURE;
	}

	if (!filter->fi_filter_type) {
		tlshd_log_error("Filter '%s' has no type specified",
				filter->fi_name);
		tlshd_tags_filter_free(filter);
		current->ps_current_filter = NULL;
		return PS_FAILURE;
	}
	if (!filter->fi_filter_type->ft_validate) {
		tlshd_log_error("Filter '%s' uses unimplemented filter type",
				filter->fi_name);
		tlshd_tags_filter_free(filter);
		current->ps_current_filter = NULL;
		return PS_FAILURE;
	}
	if (!filter->fi_filter_type->ft_validate(filter)) {
		tlshd_tags_filter_free(filter);
		current->ps_current_filter = NULL;
		return PS_FAILURE;
	}

	{
		struct tlshd_tags_filter *existing;

		existing = g_hash_table_lookup(tlshd_tags_filter_hash,
					       filter->fi_name);
		if (existing) {
			tlshd_log_error("Duplicate filter name '%s' (defined in %s and %s)",
					filter->fi_name, existing->fi_filename,
					filter->fi_filename);
			tlshd_tags_filter_free(filter);
			current->ps_current_filter = NULL;
			return PS_FAILURE;
		}
	}

	if (tlshd_debug > 3)
		tlshd_log_debug("Adding filter '%s' to the filter hash",
				filter->fi_name);
	g_hash_table_insert(tlshd_tags_filter_hash, filter->fi_name,
			    (gpointer)filter);
	current->ps_current_filter = NULL;
	return PS_FILTER;
}

///@}

/** @name tagsYamlFsm
 *
 * YAML parser finite state machine
 */

///@{

typedef enum tlshd_tags_fsm_state_index
	(*tlshd_tags_action_fn)(struct tlshd_tags_parser_state *current);

/**
 * @struct tlshd_tags_fsm_transition
 * @brief One edge of the FSM transition graph
 */
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

/**
 * @var tlshd_tags_fsm_state_table
 * @brief YAML parser finite state machine table
 */
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
	TERMINAL_STATE(PS_UNEXPECTED_INPUT_TOKEN),
	TERMINAL_STATE(PS_FAILURE),
};

/**
 * @brief Process a YAML parsing event
 * @param [in,out]  current  Current YAML parser state
 *
 * Each libyaml event produces zero or one input tokens.
 * tlshd_tags_process_yaml_event() evaluates the event token based
 * on the current parser state, then advances to the next FSM state.
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
		tlshd_log_debug("ps_state=%s, unexpected event: %s",
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

/**
 * @brief Read in one tag definition file
 * @param[in]      filename pathname of file containing tag specifications
 */
static void tlshd_tags_parse_file(const char *filename)
{
	struct tlshd_tags_parser_state current;
	yaml_parser_t parser;
	FILE *fh;

	if (!yaml_parser_initialize(&parser)) {
		tlshd_log_error("Failed to initialize parser");
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
	current.ps_current_filename = filename;
	current.ps_current_filter = NULL;
	do {
		if (!yaml_parser_parse(&parser, &current.ps_yaml_event)) {
			tlshd_log_error("Parser error %d in file '%s'",
					parser.error, filename);
			if (current.ps_current_filter) {
				tlshd_tags_filter_free(current.ps_current_filter);
				current.ps_current_filter = NULL;
			}
			break;
		}
		tlshd_tags_process_yaml_event(&current);
		yaml_event_delete(&current.ps_yaml_event);

		if (current.ps_fsm_state == PS_FAILURE ||
		    current.ps_fsm_state == PS_UNEXPECTED_INPUT_TOKEN) {
			tlshd_log_error("Tag parsing failed, line: %zu column: %zu file: %s",
					parser.mark.line + 1,
					parser.mark.column,
					filename);
			break;
		}
	} while (current.ps_fsm_state != PS_STOP);

	if (current.ps_current_filter) {
		tlshd_tags_filter_free(current.ps_current_filter);
		current.ps_current_filter = NULL;
	}

	yaml_parser_delete(&parser);
	fclose(fh);
}

/**
 * @brief Read all the tag definition files in one directory
 * @param[in]      tagsdir pathname of directory containing files that define tags
 *
 * @retval true   Directory has been read without a permanent error
 * @retval false  A permanent error occurred
 */
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

///@}

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
bool tlshd_tags_config_init(const char *tagsdir)
{
	if (!tlshd_tags_name_init())
		goto out;
	if (!tlshd_tags_filter_type_hash_init())
		goto name;
	if (!tlshd_tags_filter_hash_init())
		goto filter_type_hash;

	if (!tlshd_tags_read_directory(tagsdir))
		goto filter_hash;

	return true;

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
 * @brief Release all session tag-related resources
 *
 */
void tlshd_tags_config_shutdown(void)
{
	tlshd_tags_filter_hash_destroy();
	tlshd_tags_filter_type_hash_destroy();
	tlshd_tags_name_destroy();
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
