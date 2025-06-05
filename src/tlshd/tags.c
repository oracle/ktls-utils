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
#include <time.h>

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
 * @struct tlshd_tags_tag
 * @brief Associates a tag name with filter lists for session matching
 *
 * Filters are separated into inverted and non-inverted lists at parse
 * time. A tag matches when all non-inverted filters match and all
 * inverted filters do not match.
 */
struct tlshd_tags_tag {
	gchar				*ta_name;
	GPtrArray			*ta_noninverted_filters;
	GPtrArray			*ta_inverted_filters;

	bool				ta_matched;
};

/**
 * @var tlshd_tags_tag_hash
 * @brief Maps tag names to definitions for O(1) lookup during handshake
 */
static GHashTable *tlshd_tags_tag_hash;

/**
 * @struct tlshd_tags_parser_state
 * @brief Global parser state
 */
struct tlshd_tags_parser_state {
	yaml_event_t			ps_yaml_event;

	enum tlshd_tags_fsm_state_index	ps_fsm_state;

	const char			*ps_current_filename;
	struct tlshd_tags_filter	*ps_current_filter;
	struct tlshd_tags_tag		*ps_current_tag;
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
	else if (strcmp(mapping, "tags") == 0)
		return PS_TAGS;

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

/** @name tagsTags
 *
 * TLS session tags
 */

///@{

/**
 * @brief GPtrArray element cleanup callback for filter name strings
 * @param[in]     data       NUL-terminated C string containing filter name
 * @param[in]     user_data  Unused
 */
static void tlshd_tags_name_free_cb(gpointer data,
				    __attribute__ ((unused)) gpointer user_data)
{
	g_free(data);
}

/**
 * @brief Free tag object
 * @param[in]     tag  TLS session tag to be released
 */
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

/**
 * @brief Free the tag hash table
 */
static void tlshd_tags_tag_hash_destroy(void)
{
	if (!tlshd_tags_tag_hash)
		return;

	g_hash_table_destroy(tlshd_tags_tag_hash);
	tlshd_tags_tag_hash = NULL;
}

/**
 * @brief Initialize the tag hash table
 *
 * @retval true   Tag hash table initialization succeeded
 * @retval false  Tag hash table initialization failed
 */
static bool tlshd_tags_tag_hash_init(void)
{
	tlshd_tags_tag_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						    NULL,
						    (GDestroyNotify)tlshd_tags_tag_free);
	return tlshd_tags_tag_hash != NULL;
}

/**
 * @brief Create a new tag and make it the current tag
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
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
	if (!tag->ta_name || !tag->ta_noninverted_filters ||
	    !tag->ta_inverted_filters)
		goto free;

	current->ps_current_tag = tag;
	return PS_TAG_KEYS;

free:
	tlshd_tags_tag_free(tag);
err0:
	tlshd_log_error("Failed to allocate new tag");
	return PS_FAILURE;
}

/**
 * @brief Start parsing a tag specification
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_key_set(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	const char *key = (const char *)event->data.scalar.value;

	if (strcmp(key, "filter") == 0)
		return PS_TAG_VALUE_FILTER;

	tlshd_log_error("Unexpected tag attribute: %s", key);
	return PS_UNEXPECTED_INPUT_TOKEN;
}

/**
 * @brief Add a filter to a tag object
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_filter_add(struct tlshd_tags_parser_state *current)
{
	const yaml_event_t *event = &current->ps_yaml_event;
	gchar *value = (gchar *)event->data.scalar.value;
	GPtrArray *filters;
	gchar *filter_name;

	if (!current->ps_current_tag) {
		tlshd_log_error("No current tag");
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

	if (!g_hash_table_lookup(tlshd_tags_filter_hash, value)) {
		tlshd_log_error("Tag '%s' references undefined filter '%s'",
				current->ps_current_tag->ta_name, value);
		return PS_FAILURE;
	}

	filter_name = g_strdup((const gchar *)value);
	if (!filter_name) {
		tlshd_log_error("Failed to allocate filter name");
		return PS_FAILURE;
	}

	tlshd_log_debug("Adding filter: '%s' to tag '%s'", (const char *)value,
			current->ps_current_tag->ta_name);
	g_ptr_array_add(filters, filter_name);
	return PS_TAG_VALUE_FILTER_LIST;
}

/**
 * @brief Validate and insert a tag into the tag hash table
 * @param [in,out]  current  Current YAML parser state
 *
 * @returns the next FSM state
 */
static enum tlshd_tags_fsm_state_index
tlshd_tags_tag_validate(struct tlshd_tags_parser_state *current)
{
	struct tlshd_tags_tag *tag = current->ps_current_tag;
	struct tlshd_tags_tag *existing;

	if (!tag) {
		tlshd_log_error("No current tag");
		return PS_FAILURE;
	}

	existing = g_hash_table_lookup(tlshd_tags_tag_hash, tag->ta_name);
	if (existing) {
		tlshd_log_error("Duplicate tag name '%s'", tag->ta_name);
		tlshd_tags_tag_free(tag);
		current->ps_current_tag = NULL;
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
	FSM_STATE(PS_TAGS, tlshd_tags_transitions_tags),
	FSM_STATE(PS_TAG, tlshd_tags_transitions_tag),
	FSM_STATE(PS_TAG_KEYS, tlshd_tags_transitions_tag_keys),
	FSM_STATE(PS_TAG_KEY, tlshd_tags_transitions_tag_key),
	FSM_STATE(PS_TAG_VALUE_FILTER, tlshd_tags_transitions_tag_value_filter),
	FSM_STATE(PS_TAG_VALUE_FILTER_LIST, tlshd_tags_transitions_tag_value_filter_list),
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
	current.ps_current_tag = NULL;
	do {
		if (!yaml_parser_parse(&parser, &current.ps_yaml_event)) {
			tlshd_log_error("Parser error %d in file '%s'",
					parser.error, filename);
			if (current.ps_current_filter) {
				tlshd_tags_filter_free(current.ps_current_filter);
				current.ps_current_filter = NULL;
			}
			if (current.ps_current_tag) {
				tlshd_tags_tag_free(current.ps_current_tag);
				current.ps_current_tag = NULL;
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
	if (current.ps_current_tag) {
		tlshd_tags_tag_free(current.ps_current_tag);
		current.ps_current_tag = NULL;
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
 * @brief Wrap Glib's pattern match API
 * @param[in]     filter  TLS session tag filter
 * @param[in]     string  NUL-terminated C string
 *
 * Note: g_pattern_match() was deprecated in GLib 2.70.
 *
 * @retval true   "string" matches "filter"'s pattern argument
 * @retval false  "string" does not match "filter"'s pattern argument
 */
static bool
tlshd_tags_filter_type_match_string(struct tlshd_tags_filter *filter, gchar *string)
{
#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH_STRING
	return g_pattern_spec_match_string(filter->fi_pattern_spec,
					   string);
#else
	return g_pattern_match(filter->fi_pattern_spec,
			      strlen(string), string, NULL);
#endif
}

/**
 * @brief No filter type parameters to validate
 * @param[in]     filter  Unused
 *
 * @retval true  Filter object is valid
 */
static bool
tlshd_tags_filter_type_no_parameters(__attribute__ ((unused)) struct tlshd_tags_filter *filter)
{
	return true;
}

/**
 * @brief Validate a pattern filter
 * @param[in]     filter  Filter to be validated
 *
 * @retval true   Filter object is valid
 * @retval false  Filter object is not valid
 */
static bool
tlshd_tags_filter_type_validate_pattern(struct tlshd_tags_filter *filter)
{
	unsigned int wildcard_count = 0;
	const char *p;

	if (!filter->fi_pattern) {
		tlshd_log_error("Filter '%s' is missing a pattern.",
				filter->fi_name);
		return false;
	}

	for (p = filter->fi_pattern; *p; p++)
		if (*p == '*' || *p == '?')
			wildcard_count++;
	if (wildcard_count > 16) {
		tlshd_log_error("Pattern for filter '%s' contains too many wildcards (%d > 16)",
				filter->fi_name, wildcard_count);
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

/**
 * @brief Validate a purpose filter
 * @param[in]     filter  Filter to be validated
 *
 * @retval true   Filter object is valid
 * @retval false  Filter object is not valid
 */
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

/**
 * @brief Validate a time filter
 * @param[in]     filter  Filter to be validated
 *
 * @retval true   Filter object is valid
 * @retval false  Filter object is not valid
 */
static bool
tlshd_tags_filter_type_validate_time(struct tlshd_tags_filter *filter)
{
	struct tm tm;
	char *ret;

	memset(&tm, 0, sizeof(tm));
	ret = strptime(filter->fi_pattern, "%Y-%m-%d %H:%M:%S", &tm);
	if (!ret) {
		tlshd_log_error("Filter '%s': failed to parse time '%s'",
				filter->fi_name, filter->fi_pattern);
		return false;
	}
	filter->fi_time = mktime(&tm);

	if (filter->fi_purpose_mask != 0)
		tlshd_log_error("Filter '%s' key usage purpose is extraneous.",
				filter->fi_name);
	return true;
}

/**
 * @brief Convert raw bytes to a hexadecimal string
 * @param[in]     input      Bytes to be converted
 * @param[in]     input_size Count of bytes in "input"
 *
 * Caller must free returned string with g_free()
 *
 * @returns a NUL-terminated C string
 */
static gchar *
tlshd_tags_raw_to_hex(const uint8_t *input, size_t input_size)
{
	size_t i, output_size = (input_size * 2) + 1;
	gchar *c, *output;

	output = g_malloc(output_size);
	if (!output)
		return NULL;

	c = output;
	for (i = 0; i < input_size && output_size >= 2; i++) {
		snprintf(c, 3, "%.2x", input[i]);
		output_size -= 2;
		c += 2;
	}
	*c = '\0';

	return output;
}

/**
 * @brief Retrieve peer's x.509 certificate from TLS session
 * @param[in]     session   TLS session
 * @param[out]    peercert  Initialized certificate object
 *
 * On success, caller must call gnutls_x509_crt_deinit() on @peercert.
 *
 * @retval true   Certificate retrieved successfully
 * @retval false  Failed to retrieve certificate
 */
static bool
tlshd_tags_get_peer_x509_cert(gnutls_session_t session,
			      gnutls_x509_crt_t *peercert)
{
	const gnutls_datum_t *cert_list;
	unsigned int num_certs = 0;
	int ret;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		return false;
	cert_list = gnutls_certificate_get_peers(session, &num_certs);
	if (num_certs == 0)
		return false;

	ret = gnutls_x509_crt_init(peercert);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		return false;
	}
	ret = gnutls_x509_crt_import(*peercert, &cert_list[0], GNUTLS_X509_FMT_DER);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		gnutls_x509_crt_deinit(*peercert);
		return false;
	}

	return true;
}

/**
 * @brief Match an x.509 certificate signature algorithm filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_cert_signaturealgorithm(struct tlshd_tags_filter *filter,
							  gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	bool res = false;
	gchar *name;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

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

	res = tlshd_tags_filter_type_match_string(filter, name);
	tlshd_log_debug("Filter '%s' %s algorithm '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			name);
	g_free(name);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate version number filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_tbs_version(struct tlshd_tags_filter *filter,
					      gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	bool res = false;
	char version[16];
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	ret = gnutls_x509_crt_get_version(peercert);
	if (ret < 0) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	snprintf(version, sizeof(version), "%u", ret);
	res = tlshd_tags_filter_type_match_string(filter, version);
	tlshd_log_debug("Filter '%s' %s version '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			version);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate serial number filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_tbs_serial(struct tlshd_tags_filter *filter,
					     gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	uint8_t serial[128];
	size_t serial_size;
	bool res = false;
	gchar *hex;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	serial_size = sizeof(serial);
	ret = gnutls_x509_crt_get_serial(peercert, serial, &serial_size);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	hex = tlshd_tags_raw_to_hex(serial, serial_size);
	if (!hex) {
		tlshd_log_error("Filter '%s': failed to convert serial to hex",
				filter->fi_name);
		goto deinit;
	}
	res = tlshd_tags_filter_type_match_string(filter, hex);
	tlshd_log_debug("Filter '%s' %s serial '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			hex);
	g_free(hex);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate issuer filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_tbs_issuer(struct tlshd_tags_filter *filter,
					      gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	gnutls_datum_t dn;
	bool res = false;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	ret = gnutls_x509_crt_get_issuer_dn3(peercert, &dn, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	res = g_pattern_spec_match(filter->fi_pattern_spec, dn.size,
				   (const gchar *)dn.data, NULL);
#else
	res = g_pattern_match(filter->fi_pattern_spec, dn.size,
			      (const gchar *)dn.data, NULL);
#endif

	tlshd_log_debug("Filter '%s' %s issuer '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			dn.data);
	gnutls_free(dn.data);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate "not before" filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_tbs_validity_notbefore(struct tlshd_tags_filter *filter,
							 gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	time_t activation_time;
	bool res = false;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

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
	return res;
}

/**
 * @brief Match an x.509 certificate "not after" filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_tbs_validity_notafter(struct tlshd_tags_filter *filter,
							gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	time_t expiration_time;
	bool res = false;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	expiration_time = gnutls_x509_crt_get_expiration_time(peercert);
	if (expiration_time == (time_t)-1) {
		tlshd_log_error("Failed to retrieve expiration time.");
		goto deinit;
	}

	res = (filter->fi_time <= expiration_time);

	tlshd_log_debug("Filter '%s' %s validity.notAfter '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			filter->fi_pattern);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate subject filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_tbs_subject(struct tlshd_tags_filter *filter,
					      gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	gnutls_datum_t dn;
	bool res = false;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	ret = gnutls_x509_crt_get_dn3(peercert, &dn, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

#ifdef HAVE_GLIB_G_PATTERN_SPEC_MATCH
	res = g_pattern_spec_match(filter->fi_pattern_spec, dn.size,
				   (const gchar *)dn.data, NULL);
#else
	res = g_pattern_match(filter->fi_pattern_spec, dn.size,
			      (const gchar *)dn.data, NULL);
#endif

	tlshd_log_debug("Filter '%s' %s subject '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			dn.data);
	gnutls_free(dn.data);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate key usage filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_extension_keyusage(struct tlshd_tags_filter *filter,
						     gnutls_session_t session)
{
	unsigned int key_usage, critical;
	gnutls_x509_crt_t peercert;
	bool res = false;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	ret = gnutls_x509_crt_get_key_usage(peercert, &key_usage, &critical);
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
	return res;
}

/**
 * @brief Match an x.509 certificate fingerprint filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_derived_fingerprint(struct tlshd_tags_filter *filter,
						      gnutls_session_t session)
{
	bool sha1_res, sha256_res, res = false;
	uint8_t fingerprint[64];
	size_t size = sizeof(fingerprint);
	gnutls_x509_crt_t peercert;
	gchar *hex;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	ret = gnutls_x509_crt_get_fingerprint(peercert, GNUTLS_DIG_SHA1,
					      fingerprint, &size);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	hex = tlshd_tags_raw_to_hex(fingerprint, size);
	if (!hex) {
		tlshd_log_error("Filter '%s': failed to convert fingerprint to hex",
				filter->fi_name);
		goto deinit;
	}
	sha1_res = tlshd_tags_filter_type_match_string(filter, hex);
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
		tlshd_log_error("Filter '%s': failed to convert fingerprint to hex",
				filter->fi_name);
		goto deinit;
	}
	sha256_res = tlshd_tags_filter_type_match_string(filter, hex);
	g_free(hex);

	res = sha1_res || sha256_res;

	tlshd_log_debug("Filter '%s' %s fingerprint '%s'",
			filter->fi_name,
			res ? "matched" : "did not match",
			filter->fi_pattern);
deinit:
	gnutls_x509_crt_deinit(peercert);
	return res;
}

/**
 * @brief Match an x.509 certificate self-signage filter
 * @param[in]     filter   Filter to be matched
 * @param[in]     session  TLS session to be matched
 *
 * @retval true   Filter parameters matched
 * @retval false  Filter parameters did not match
 */
static bool
tlshd_tags_filter_type_match_x509_derived_selfsigned(struct tlshd_tags_filter *filter,
						     gnutls_session_t session)
{
	gnutls_x509_crt_t peercert;
	gnutls_datum_t issuer, subject;
	bool res = false;
	int ret;

	if (!tlshd_tags_get_peer_x509_cert(session, &peercert))
		return false;

	ret = gnutls_x509_crt_get_issuer_dn3(peercert, &issuer, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		goto deinit;
	}

	ret = gnutls_x509_crt_get_dn3(peercert, &subject, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		gnutls_free(issuer.data);
		goto deinit;
	}

	if (issuer.size == subject.size &&
	    memcmp(issuer.data, subject.data, issuer.size) == 0)
		res = true;

	gnutls_free(subject.data);
	gnutls_free(issuer.data);

deinit:
	tlshd_log_debug("Filter '%s' x.509 cert %s self-signed",
			filter->fi_name, res ? "is" : "is not");
	gnutls_x509_crt_deinit(peercert);
	return res;
}


/**
 * @var tlshd_tags_static_filter_types
 * @brief Fixed, internally-defined tag filter types
 */
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
	/*
	 * x509.tbs.signature (RFC 5280, Section 4.1.2.3) not implemented:
	 * redundant with x509.cert.signatureAlgorithm.
	 */
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
	/*
	 * x509.extension.extendedKeyUsage (RFC 5280, Section 4.2.1.12)
	 * not implemented: requires OID-based filtering.
	 */

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
		.ft_validate		= tlshd_tags_filter_type_no_parameters,
		.ft_match		= tlshd_tags_filter_type_match_x509_derived_selfsigned,
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
		tlshd_log_error("Failed to allocate 'filter type' hash table");
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

/**
 * @struct tlshd_tags_match_args
 * @brief Tag match context
 */
struct tlshd_tags_match_args {
	struct tlshd_tags_tag		*ma_tag;
	gnutls_session_t		ma_session;
	bool				ma_filter_matched;
};

/**
 * @brief Match an inverted filter
 * @param[in]     data       Name of filter to match
 * @param[in,out] user_data  Context containing tag and session information
 */
static void tlshd_tags_x509_nomatch_filters_cb(gpointer data, gpointer user_data)
{
	struct tlshd_tags_match_args *args = (struct tlshd_tags_match_args *)user_data;
	gchar *filter_name = (gchar *)data;
	struct tlshd_tags_filter *filter;

	/* A previous filter matched. No need to check more of this
	 * tag's inverting filters. */
	if (args->ma_filter_matched)
		return;

	filter = g_hash_table_lookup(tlshd_tags_filter_hash, filter_name);
	if (!filter) {
		args->ma_filter_matched = false;
		tlshd_log_debug("Failed to find filter '%s'", filter_name);
		return;
	}
	if (!filter->fi_filter_type->ft_match) {
		args->ma_filter_matched = false;
		return;
	}

	args->ma_filter_matched = filter->fi_filter_type->ft_match(filter, args->ma_session);
}

/**
 * @brief Match a non-inverted filter
 * @param[in]     data       Name of filter to match
 * @param[in,out] user_data  Context containing tag and session information
 */
static void tlshd_tags_x509_match_filters_cb(gpointer data, gpointer user_data)
{
	struct tlshd_tags_match_args *args = (struct tlshd_tags_match_args *)user_data;
	gchar *filter_name = (gchar *)data;
	struct tlshd_tags_filter *filter;

	/* A previous filter failed to match. No need to check more of
	 * this tag's non-inverting filters. */
	if (!args->ma_filter_matched)
		return;

	filter = g_hash_table_lookup(tlshd_tags_filter_hash, filter_name);
	if (!filter) {
		args->ma_filter_matched = false;
		tlshd_log_debug("Failed to find filter '%s'", filter_name);
		return;
	}
	if (!filter->fi_filter_type->ft_match) {
		args->ma_filter_matched = true;
		return;
	}

	args->ma_filter_matched = filter->fi_filter_type->ft_match(filter, args->ma_session);
}

/**
 * @brief match certificate against configured tags
 * @param[in]     session  session to assign tags to
 *
 * Side-effect: The ta_matched boolean is set in each tag in the
 * global tag list that is matched. When this function is called in
 * a child process, the parent process's tag list is not changed
 * (the parent's tag list is copied-on-write when the child address
 * space is created by fork(2)).
 */
void tlshd_tags_match_session(gnutls_session_t session)
{
	GHashTableIter iter;
	gpointer key, value;

	if (!tlshd_tags_tag_hash)
		return;

	/* Visit each tag in the global hash */
	g_hash_table_iter_init(&iter, tlshd_tags_tag_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct tlshd_tags_match_args args = {
			.ma_tag			= (struct tlshd_tags_tag *)value,
			.ma_session		= session,
		};
		bool inverted_matched;

		args.ma_tag->ta_matched = false;

		/* Visit each inverting filter in the tag */
		args.ma_filter_matched = false;
		g_ptr_array_foreach(args.ma_tag->ta_inverted_filters,
				    tlshd_tags_x509_nomatch_filters_cb,
				    (gpointer)&args);
		inverted_matched = args.ma_filter_matched;

		/* Visit each non-inverting filter in the tag */
		args.ma_filter_matched = true;
		g_ptr_array_foreach(args.ma_tag->ta_noninverted_filters,
				    tlshd_tags_x509_match_filters_cb,
				    (gpointer)&args);

		/*
		 * Set tag->ta_matched only if:
		 * - none of the inverting filters matched, and
		 * - all the tag's non-inverting filters matched
		 */
		args.ma_tag->ta_matched = !inverted_matched && args.ma_filter_matched;
	}
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
 * @brief Release all session tag-related resources
 *
 */
void tlshd_tags_config_shutdown(void)
{
	tlshd_tags_tag_hash_destroy();
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
