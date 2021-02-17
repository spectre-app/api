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

#ifndef _MPW_ALGORITHM_H
#define _MPW_ALGORITHM_H

#include "mpw-types.h"

/** Derive the user key for a user based on their name and user secret.
 * @return A MPUserKey value (allocated) or NULL if the userName or userSecret is missing, the algorithm is unknown, or an algorithm error occurred. */
const MPUserKey *mpw_user_key(
        const char *userName, const char *userSecret, const MPAlgorithmVersion algorithmVersion);

/** Generate a result token for a user from the user's user key and result parameters.
 * @param resultParam A parameter for the resultType.  For stateful result types, the output of mpw_site_state.
 * @return A C-string (allocated) or NULL if the userKey or siteName is missing, the algorithm is unknown, or an algorithm error occurred. */
const char *mpw_site_result(
        const MPUserKey *userKey, const char *siteName,
        const MPResultType resultType, const char *resultParam,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext);

/** Encrypt a result token for stateful persistence.
 * @param resultParam A parameter for the resultType.  For stateful result types, the desired mpw_site_result.
 * @return A C-string (allocated) or NULL if the userKey, siteName or resultType's resultParam is missing, the algorithm is unknown, or an algorithm error occurred. */
const char *mpw_site_state(
        const MPUserKey *userKey, const char *siteName,
        const MPResultType resultType, const char *resultParam,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext);

/** Derive the result key for a user from the user's user key and result parameters.
 * @return An MPSiteKey value (allocated) or NULL if the userKey or siteName is missing, the algorithm is unknown, or an algorithm error occurred. */
const MPSiteKey *mpw_site_key(
        const MPUserKey *userKey, const char *siteName,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext);

/** @return An identicon (static) that represents the user's identity. */
const MPIdenticon mpw_identicon(
        const char *userName, const char *userSecret);
/** @return A C-string encoded representation (allocated) of the given identicon or NULL if the identicon is unset. */
const char *mpw_identicon_encode(
        const MPIdenticon identicon);
/** @return An identicon (static) decoded from the given encoded identicon representation or an identicon with empty fields if the identicon could not be parsed. */
const MPIdenticon mpw_identicon_encoded(
        const char *encoding);

#endif // _MPW_ALGORITHM_H
