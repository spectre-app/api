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

#include "mpw-algorithm.h"
#include "mpw-algorithm_v0.h"
#include "mpw-algorithm_v1.h"
#include "mpw-algorithm_v2.h"
#include "mpw-algorithm_v3.h"
#include "mpw-util.h"

MP_LIBS_BEGIN
#include <string.h>
MP_LIBS_END

const MPUserKey *mpw_user_key(
        const char *userName, const char *userSecret, const MPAlgorithmVersion algorithmVersion) {

    if (userName && !strlen( userName ))
        userName = NULL;
    if (userSecret && !strlen( userSecret ))
        userSecret = NULL;

    trc( "-- mpw_user_key (algorithm: %u)", algorithmVersion );
    trc( "userName: %s", userName );
    trc( "userSecret.id: %s", userSecret? mpw_id_buf( (uint8_t *)userSecret, strlen( userSecret ) ).hex: NULL );
    if (!userName) {
        err( "Missing userName" );
        return NULL;
    }
    if (!userSecret) {
        err( "Missing userSecret" );
        return NULL;
    }

    MPUserKey *userKey = memcpy( malloc( sizeof( MPUserKey ) ),
            &(MPUserKey){ .algorithm = algorithmVersion }, sizeof( MPUserKey ) );

    bool success = false;
    switch (algorithmVersion) {
        case MPAlgorithmVersionV0:
            success = mpw_user_key_v0( userKey, userName, userSecret );
            break;
        case MPAlgorithmVersionV1:
            success = mpw_user_key_v1( userKey, userName, userSecret );
            break;
        case MPAlgorithmVersionV2:
            success = mpw_user_key_v2( userKey, userName, userSecret );
            break;
        case MPAlgorithmVersionV3:
            success = mpw_user_key_v3( userKey, userName, userSecret );
            break;
        default:
            err( "Unsupported version: %d", algorithmVersion );
    }

    if (success)
        return userKey;

    mpw_free( &userKey, sizeof( MPUserKey ) );
    return NULL;
}

const MPSiteKey *mpw_site_key(
        const MPUserKey *userKey, const char *siteName,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }
    if (!siteName) {
        err( "Missing siteName" );
        return NULL;
    }

    trc( "-- mpw_site_key (algorithm: %u)", userKey->algorithm );
    trc( "siteName: %s", siteName );
    trc( "keyCounter: %d", keyCounter );
    trc( "keyPurpose: %d (%s)", keyPurpose, mpw_purpose_name( keyPurpose ) );
    trc( "keyContext: %s", keyContext );

    MPSiteKey *siteKey = memcpy( malloc( sizeof( MPSiteKey ) ),
            &(MPSiteKey){ .algorithm = userKey->algorithm }, sizeof( MPSiteKey ) );

    bool success = false;
    switch (userKey->algorithm) {
        case MPAlgorithmVersionV0:
            success = mpw_site_key_v0( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case MPAlgorithmVersionV1:
            success = mpw_site_key_v1( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case MPAlgorithmVersionV2:
            success = mpw_site_key_v2( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case MPAlgorithmVersionV3:
            success = mpw_site_key_v3( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        default:
            err( "Unsupported version: %d", userKey->algorithm );
    }

    if (success)
        return siteKey;

    mpw_free( &siteKey, sizeof( MPSiteKey ) );
    return NULL;
}

const char *mpw_site_result(
        const MPUserKey *userKey, const char *siteName,
        const MPResultType resultType, const char *resultParam,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }

    const MPSiteKey *siteKey = mpw_site_key( userKey, siteName, keyCounter, keyPurpose, keyContext );
    if (!siteKey) {
        err( "Missing siteKey" );
        return NULL;
    }

    trc( "-- mpw_site_result (algorithm: %u)", userKey->algorithm );
    trc( "resultType: %d (%s)", resultType, mpw_type_short_name( resultType ) );
    trc( "resultParam: %s", resultParam );

    if (resultType == MPResultTypeNone) {
        return NULL;
    }
    else if (resultType & MPResultTypeClassTemplate) {
        switch (userKey->algorithm) {
            case MPAlgorithmVersionV0:
                return mpw_site_template_password_v0( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV1:
                return mpw_site_template_password_v1( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV2:
                return mpw_site_template_password_v2( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV3:
                return mpw_site_template_password_v3( userKey, siteKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                return NULL;
        }
    }
    else if (resultType & MPResultTypeClassStateful) {
        switch (userKey->algorithm) {
            case MPAlgorithmVersionV0:
                return mpw_site_crypted_password_v0( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV1:
                return mpw_site_crypted_password_v1( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV2:
                return mpw_site_crypted_password_v2( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV3:
                return mpw_site_crypted_password_v3( userKey, siteKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                return NULL;
        }
    }
    else if (resultType & MPResultTypeClassDerive) {
        switch (userKey->algorithm) {
            case MPAlgorithmVersionV0:
                return mpw_site_derived_password_v0( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV1:
                return mpw_site_derived_password_v1( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV2:
                return mpw_site_derived_password_v2( userKey, siteKey, resultType, resultParam );
            case MPAlgorithmVersionV3:
                return mpw_site_derived_password_v3( userKey, siteKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                return NULL;
        }
    }
    else {
        err( "Unsupported password type: %d", resultType );
    }

    return NULL;
}

const char *mpw_site_state(
        const MPUserKey *userKey, const char *siteName,
        const MPResultType resultType, const char *resultParam,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }

    const MPSiteKey *siteKey = mpw_site_key( userKey, siteName, keyCounter, keyPurpose, keyContext );
    if (!siteKey) {
        err( "Missing siteKey" );
        return NULL;
    }
    if (!resultParam) {
        err( "Missing resultParam" );
        return NULL;
    }

    trc( "-- mpw_site_state (algorithm: %u)", userKey->algorithm );
    trc( "resultType: %d (%s)", resultType, mpw_type_short_name( resultType ) );
    trc( "resultParam: %zu bytes = %s", resultParam? strlen( resultParam ): 0, resultParam );

    if (resultType == MPResultTypeNone) {
        return NULL;
    }

    switch (userKey->algorithm) {
        case MPAlgorithmVersionV0:
            return mpw_site_state_v0( userKey, siteKey, resultType, resultParam );
        case MPAlgorithmVersionV1:
            return mpw_site_state_v1( userKey, siteKey, resultType, resultParam );
        case MPAlgorithmVersionV2:
            return mpw_site_state_v2( userKey, siteKey, resultType, resultParam );
        case MPAlgorithmVersionV3:
            return mpw_site_state_v3( userKey, siteKey, resultType, resultParam );
        default:
            err( "Unsupported version: %d", userKey->algorithm );
            return NULL;
    }
}

static const char *mpw_identicon_leftArms[] = { "╔", "╚", "╰", "═" };
static const char *mpw_identicon_bodies[] = { "█", "░", "▒", "▓", "☺", "☻" };
static const char *mpw_identicon_rightArms[] = { "╗", "╝", "╯", "═" };
static const char *mpw_identicon_accessories[] = {
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘", "☢", "☣",
        "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟",
        "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌"
};

const MPIdenticon mpw_identicon(
        const char *userName, const char *userSecret) {

    uint8_t seed[32] = { 0 };
    if (userName && strlen( userName ) && userSecret && strlen( userSecret ))
        if (!mpw_hash_hmac_sha256( seed,
                (const uint8_t *)userSecret, strlen( userSecret ),
                (const uint8_t *)userName, strlen( userName ) )) {
            mpw_zero( &seed, sizeof( seed ) );
            return MPIdenticonUnset;
        }

    MPIdenticon identicon = {
            .leftArm = mpw_identicon_leftArms[seed[0] % (sizeof( mpw_identicon_leftArms ) / sizeof( *mpw_identicon_leftArms ))],
            .body = mpw_identicon_bodies[seed[1] % (sizeof( mpw_identicon_bodies ) / sizeof( *mpw_identicon_bodies ))],
            .rightArm = mpw_identicon_rightArms[seed[2] % (sizeof( mpw_identicon_rightArms ) / sizeof( *mpw_identicon_rightArms ))],
            .accessory = mpw_identicon_accessories[seed[3] % (sizeof( mpw_identicon_accessories ) / sizeof( *mpw_identicon_accessories ))],
            .color = (MPIdenticonColor)(seed[4] % (MPIdenticonColorLast - MPIdenticonColorFirst + 1) + MPIdenticonColorFirst),
    };
    mpw_zero( &seed, sizeof( seed ) );

    return identicon;
}

const char *mpw_identicon_encode(
        const MPIdenticon identicon) {

    if (identicon.color == MPIdenticonColorUnset)
        return NULL;

    return mpw_str( "%hhu:%s%s%s%s",
            identicon.color, identicon.leftArm, identicon.body, identicon.rightArm, identicon.accessory );
}

const MPIdenticon mpw_identicon_encoded(
        const char *encoding) {

    MPIdenticon identicon = MPIdenticonUnset;
    if (!encoding || !strlen( encoding ))
        return identicon;

    char *string = calloc( strlen( encoding ), sizeof( *string ) ), *parser = string;
    const char *leftArm = NULL, *body = NULL, *rightArm = NULL, *accessory = NULL;
    unsigned int color;

    if (string && sscanf( encoding, "%u:%s", &color, string ) == 2) {
        if (*parser && color)
            for (unsigned int s = 0; s < sizeof( mpw_identicon_leftArms ) / sizeof( *mpw_identicon_leftArms ); ++s) {
                const char *limb = mpw_identicon_leftArms[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    leftArm = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && leftArm)
            for (unsigned int s = 0; s < sizeof( mpw_identicon_bodies ) / sizeof( *mpw_identicon_bodies ); ++s) {
                const char *limb = mpw_identicon_bodies[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    body = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && body)
            for (unsigned int s = 0; s < sizeof( mpw_identicon_rightArms ) / sizeof( *mpw_identicon_rightArms ); ++s) {
                const char *limb = mpw_identicon_rightArms[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    rightArm = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && rightArm)
            for (unsigned int s = 0; s < sizeof( mpw_identicon_accessories ) / sizeof( *mpw_identicon_accessories ); ++s) {
                const char *limb = mpw_identicon_accessories[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    accessory = limb;
                    break;
                }
            }
        if (leftArm && body && rightArm && color >= MPIdenticonColorFirst && color <= MPIdenticonColorLast)
            identicon = (MPIdenticon){
                    .leftArm = leftArm,
                    .body = body,
                    .rightArm = rightArm,
                    .accessory = accessory,
                    .color = (MPIdenticonColor)color,
            };
    }

    mpw_free_string( &string );
    return identicon;
}
