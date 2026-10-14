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
#include "json.h"
#endif
SPECTRE_LIBS_END

/// Type parsing.

/** Get a token from a string by searching until the first character in delim, no farther than eol.
 * The input string reference is advanced beyond the token delimitor if one is found.
 * @param eol Pointer to the final character in the string to search, or NULL to search the full string.
 * @return A C-string (allocated) containing the token or NULL if the delim wasn't found before eol. */
const char *spectre_get_token(
        const char **in, const char *eol, const char *delim);
/** Get a boolean value as expressed by the given string.
 * @return true if the string is not NULL and holds a number larger than 0, or starts with a t (for true) or y (for yes). */
bool spectre_get_bool(
        const char *in);
/** Get an unsigned 32-bit integer as expressed by the given string.
 * @return The integer held by the string if between [min, max], or (uint32_t)ERR otherwise. */
uint32_t spectre_get_u32(
        const char *in, const uint32_t min, const uint32_t max);
/** Convert an RFC 3339 UTC time string (YYYY-MM-DDTHH:MM:SSZ) into Epoch time.
 * @return ERR if the string could not be parsed. */
time_t spectre_get_time(
        const char *in);
/** Convert epoch time into an RFC 3339 time string.
 * @return An RFC 3339 encoded string (static, overwritten by the next call). */
const char *spectre_set_time(
        time_t time);


/// Spectre.

/** Calculate a user key, unless the given user key is already current for the algorithm and user name.
 * The user secret is not compared: free the user key when the user secret changes.
 * @param userKey A buffer (allocated); replaced by a newly derived key if necessary.
 * @return false if an error occurred during the derivation of the user key. */
bool spectre_update_user_key(
        const SpectreUserKey **userKey, const SpectreAlgorithm algorithm,
        const char *userName, const char *userSecret);


/// JSON parsing.

#if SPECTRE_JSON
/** Translate a JSON object tree into a source-agnostic data object.
 * @param data A Spectre data object or NULL.
 * @param obj A JSON object tree or NULL. */
void spectre_set_json_data(
        SpectreMarshalledData *data, json_object *obj);
#endif

#endif // _SPECTRE_MARSHAL_UTIL_H
