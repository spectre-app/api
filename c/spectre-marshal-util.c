// =============================================================================
// Created by Maarten Billemont on 2017-07-28.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

#include "spectre-marshal-util.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
#include <math.h>
SPECTRE_LIBS_END

const char *spectre_get_token(const char **in, const char *eol, const char *delim) {

    // Skip leading spaces.
    for (; **in == ' '; ++*in);

    // Find characters up to the first delim.
    size_t len = strcspn( *in, delim );
    const char *token = len <= (size_t)(eol - *in)? spectre_strndup( *in, len ): NULL;

    // Advance past the delimitor.
    *in = min( eol, *in + len + 1 );
    return token;
}

bool spectre_get_bool(const char *in) {

    return in && (in[0] == 'y' || in[0] == 't' || strtol( in, NULL, 10 ) > 0);
}

time_t spectre_get_timegm(const char *in) {

    // TODO: Support for parsing non-UTC time strings
    // Parse as a UTC timestamp, into a tm.
    struct tm tm = { .tm_isdst = -1 };
    if (in && sscanf( in, "%4d-%2d-%2dT%2d:%2d:%2dZ",
            &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
            &tm.tm_hour, &tm.tm_min, &tm.tm_sec ) == 6) {
        tm.tm_year -= 1900; // tm_year 0 = rfc3339 year  1900
        tm.tm_mon -= 1;     // tm_mon  0 = rfc3339 month 1

        // mktime interprets tm as being local, we need to offset back to UTC (timegm/tm_gmtoff are non-standard).
        time_t local_time = mktime( &tm ), local_dst = tm.tm_isdst > 0? 3600: 0;
        time_t gmtoff = local_time + local_dst - mktime( gmtime( &local_time ) );
        return local_time + gmtoff;
    }

    return ERR;
}

bool spectre_update_user_key(const SpectreUserKey **userKey, SpectreAlgorithm *userKeyAlgorithm, const SpectreAlgorithm targetKeyAlgorithm,
        const char *userName, const char *userSecret) {

    if (!userKey || !userKeyAlgorithm)
        return false;

    if (!*userKey || *userKeyAlgorithm != targetKeyAlgorithm) {
        spectre_free( userKey, sizeof( **userKey ) );
        *userKeyAlgorithm = targetKeyAlgorithm;
        *userKey = spectre_user_key( userName, userSecret, *userKeyAlgorithm );
    }

    return *userKey != NULL;
}

#if SPECTRE_JSON

json_object *spectre_get_json_object(
        json_object *obj, const char *key, const bool create) {

    if (!obj)
        return NULL;

    json_object *json_value = NULL;
    if (!json_object_object_get_ex( obj, key, &json_value ) || !json_value)
        if (!create || json_object_object_add( obj, key, json_value = json_object_new_object() ) != OK) {
            trc( "Missing value for: %s", key );
            json_value = NULL;
        }

    return json_value;
}

const char *spectre_get_json_string(
        json_object *obj, const char *key, const char *defaultValue) {

    json_object *json_value = spectre_get_json_object( obj, key, false );
    if (!json_value)
        return defaultValue;

    return json_object_get_string( json_value );
}

int64_t spectre_get_json_int(
        json_object *obj, const char *key, const int64_t defaultValue) {

    json_object *json_value = spectre_get_json_object( obj, key, false );
    if (!json_value)
        return defaultValue;

    return json_object_get_int64( json_value );
}

bool spectre_get_json_boolean(
        json_object *obj, const char *key, const bool defaultValue) {

    json_object *json_value = spectre_get_json_object( obj, key, false );
    if (!json_value)
        return defaultValue;

    return json_object_get_boolean( json_value ) == true;
}

static bool spectre_marshal_data_filter_keyed(SpectreMarshalledData *child, __unused void *args) {

    return child->obj_key != NULL;
}

static bool spectre_marshal_data_filter_unkeyed(SpectreMarshalledData *child, __unused void *args) {

    return child->obj_key == NULL;
}

void spectre_set_json_data(
        SpectreMarshalledData *data, json_object *obj) {

    if (!data)
        return;

    json_type type = json_object_get_type( obj );
    data->is_null = type == json_type_null;
    data->is_bool = type == json_type_boolean;

    if (type == json_type_boolean)
        data->num_value = json_object_get_boolean( obj );
    else if (type == json_type_double)
        data->num_value = json_object_get_double( obj );
    else if (type == json_type_int)
        data->num_value = json_object_get_int64( obj );
    else
        data->num_value = NAN;

    const char *str = NULL;
    if (type == json_type_string || !isnan( data->num_value ))
        str = json_object_get_string( obj );
    if (!str || !data->str_value || strcmp( str, data->str_value ) != OK) {
        spectre_free_string( &data->str_value );
        data->str_value = spectre_strdup( str );
    }

    // Clean up children
    if (type != json_type_object && type != json_type_array) {
        spectre_marshal_data_filter( data, spectre_marshal_data_filter_empty, NULL );
    }
    else if (type == json_type_array) {
        spectre_marshal_data_filter( data, spectre_marshal_data_filter_unkeyed, NULL );
    }
    else /* type == json_type_object */ {
        spectre_marshal_data_filter( data, spectre_marshal_data_filter_keyed, NULL );
    }

    // Object
    if (type == json_type_object) {
        json_object_iter entry;
        json_object_object_foreachC( obj, entry ) {
            SpectreMarshalledData *child = NULL;

            // Find existing child.
            for (size_t c = 0; c < data->children_count; ++c)
                if (data->children[c].obj_key == entry.key ||
                    (data->children[c].obj_key && entry.key && strcmp( data->children[c].obj_key, entry.key ) == OK)) {
                    child = &data->children[c];
                    break;
                }

            // Create new child.
            if (!child) {
                if (!spectre_realloc( &data->children, NULL, SpectreMarshalledData, ++data->children_count )) {
                    --data->children_count;
                    continue;
                }
                *(child = &data->children[data->children_count - 1]) = (SpectreMarshalledData){ .obj_key = spectre_strdup( entry.key ) };
                spectre_marshal_data_set_null( child, NULL );
            }

            spectre_set_json_data( child, entry.val );
        }
    }

    // Array
    if (type == json_type_array) {
        for (size_t index = 0; index < json_object_array_length( obj ); ++index) {
            SpectreMarshalledData *child = NULL;

            if (index < data->children_count)
                child = &data->children[index];

            else {
                if (!spectre_realloc( &data->children, NULL, SpectreMarshalledData, ++data->children_count )) {
                    --data->children_count;
                    continue;
                }
                *(child = &data->children[data->children_count - 1]) = (SpectreMarshalledData){ .arr_index = index };
                spectre_marshal_data_set_null( child, NULL );
            }

            spectre_set_json_data( child, json_object_array_get_idx( obj, index ) );
        }
    }
}

#endif
