//==============================================================================
// This file is part of Spectre.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// Spectre is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Spectre is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You can find a copy of the GNU General Public License in the
// LICENSE file.  Alternatively, see <http://www.gnu.org/licenses/>.
//==============================================================================

#ifndef _SPECTRE_ALGORITHM_H
#define _SPECTRE_ALGORITHM_H

#include "spectre-types.h"

/** Derive the user key for a user based on their name and user secret.
 * @return A SpectreUserKey value (allocated) or NULL if the userName or userSecret is missing, the algorithm is unknown, or an algorithm error occurred. */
const SpectreUserKey *spectre_user_key(
        const char *userName, const char *userSecret, const SpectreAlgorithm algorithmVersion);

/** Generate a result token for a user from the user's user key and result parameters.
 * @param resultParam A parameter for the resultType.  For stateful result types, the output of spectre_site_state.
 * @return A C-string (allocated) or NULL if the userKey or siteName is missing, the algorithm is unknown, or an algorithm error occurred. */
const char *spectre_site_result(
        const SpectreUserKey *userKey, const char *siteName,
        const SpectreResultType resultType, const char *resultParam,
        const SpectreCounter keyCounter, const SpectreKeyPurpose keyPurpose, const char *keyContext);

/** Encrypt a result token for stateful persistence.
 * @param resultParam A parameter for the resultType.  For stateful result types, the desired spectre_site_result.
 * @return A C-string (allocated) or NULL if the userKey, siteName or resultType's resultParam is missing, the algorithm is unknown, or an algorithm error occurred. */
const char *spectre_site_state(
        const SpectreUserKey *userKey, const char *siteName,
        const SpectreResultType resultType, const char *resultParam,
        const SpectreCounter keyCounter, const SpectreKeyPurpose keyPurpose, const char *keyContext);

/** Derive the result key for a user from the user's user key and result parameters.
 * @return An SpectreSiteKey value (allocated) or NULL if the userKey or siteName is missing, the algorithm is unknown, or an algorithm error occurred. */
const SpectreSiteKey *spectre_site_key(
        const SpectreUserKey *userKey, const char *siteName,
        const SpectreCounter keyCounter, const SpectreKeyPurpose keyPurpose, const char *keyContext);

/** @return An identicon (static) that represents the user's identity. */
const SpectreIdenticon spectre_identicon(
        const char *userName, const char *userSecret);
/** @return A C-string encoded representation (allocated) of the given identicon or NULL if the identicon is unset. */
const char *spectre_identicon_encode(
        const SpectreIdenticon identicon);
/** @return An identicon (static) decoded from the given encoded identicon representation or an identicon with empty fields if the identicon could not be parsed. */
const SpectreIdenticon spectre_identicon_encoded(
        const char *encoding);

#endif // _SPECTRE_ALGORITHM_H
