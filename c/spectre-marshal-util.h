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

#ifndef _SPECTRE_MARSHAL_UTIL_H
#define _SPECTRE_MARSHAL_UTIL_H

#include "spectre-algorithm.h"
#include "spectre-marshal.h"

SPECTRE_LIBS_BEGIN
#include <time.h>
#if SPECTRE_JSON
#include "json-c/json.h"
#endif
SPECTRE_LIBS_END

/// Type parsing.

/** Get a token from a string by searching until the first character in delim, no farther than eol.
 * The input string reference is advanced beyond the token delimitor if one is found.
 * @return A C-string (allocated) containing the token or NULL if the delim wasn't found before eol. */
const char *spectre_get_token(
        const char **in, const char *eol, const char *delim);
/** Get a boolean value as expressed by the given string.
 * @return true if the string is not NULL and holds a number larger than 0, or starts with a t (for true) or y (for yes). */
bool spectre_get_bool(
        const char *in);
/** Convert an RFC 3339 time string into epoch time.
 * @return ERR if the string could not be parsed. */
time_t spectre_get_timegm(
        const char *in);


/// Spectre.

/** Calculate a user key if the target user key algorithm is different from the given user key algorithm.
 * @param userKey A buffer (allocated).
 * @return false if an error occurred during the derivation of the user key. */
bool spectre_update_user_key(
        const SpectreUserKey **userKey, SpectreAlgorithm *userKeyAlgorithm, const SpectreAlgorithm targetKeyAlgorithm,
        const char *userName, const char *userSecret);


/// JSON parsing.

#if SPECTRE_JSON
/** Search for an object in a JSON object tree.
 * @param key A JSON object key for the child in this object.
 * @param create If true, create and insert new objects for any missing path components.
 * @return An object (shared) or a new object (shared) installed in the tree if the path's object path was not found. */
json_object *spectre_get_json_object(
        json_object *obj, const char *key, const bool create);
/** Search for a string in a JSON object tree.
 * @param key A dot-delimited list of JSON object keys to walk toward the child object.
 * @return A C-string (shared) or defaultValue if one of the path's object keys was not found in the source object's tree. */
const char *spectre_get_json_string(
        json_object *obj, const char *key, const char *defaultValue);
/** Search for an integer in a JSON object tree.
 * @param key A dot-delimited list of JSON object keys to walk toward the child object.
 * @return The integer value or defaultValue if one of the path's object keys was not found in the source object's tree. */
int64_t spectre_get_json_int(
        json_object *obj, const char *key, const int64_t defaultValue);
/** Search for a boolean in a JSON object tree.
 * @param key A dot-delimited list of JSON object keys to walk toward the child object.
 * @return The boolean value or defaultValue if one of the path's object keys was not found in the source object's tree. */
bool spectre_get_json_boolean(
        json_object *obj, const char *key, const bool defaultValue);
/** Translate a JSON object tree into a source-agnostic data object.
 * @param data A Spectre data object or NULL.
 * @param obj A JSON object tree or NULL. */
void spectre_set_json_data(
        SpectreMarshalledData *data, json_object *obj);
#endif

#endif // _SPECTRE_MARSHAL_UTIL_H
