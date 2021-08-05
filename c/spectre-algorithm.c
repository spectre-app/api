// =============================================================================
// Created by Maarten Billemont on 2014-05-05.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

#include "spectre-algorithm.h"
#include "spectre-algorithm_v0.h"
#include "spectre-algorithm_v1.h"
#include "spectre-algorithm_v2.h"
#include "spectre-algorithm_v3.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
SPECTRE_LIBS_END

const SpectreUserKey *spectre_user_key(
        const char *userName, const char *userSecret, const SpectreAlgorithm algorithmVersion) {

    if (userName && !strlen( userName ))
        userName = NULL;
    if (userSecret && !strlen( userSecret ))
        userSecret = NULL;

    trc( "-- spectre_user_key (algorithm: %u)", algorithmVersion );
    trc( "userName: %s", userName );
    trc( "userSecret.id: %s", userSecret? spectre_id_buf( (uint8_t *)userSecret, strlen( userSecret ) ).hex: NULL );
    if (!userName) {
        err( "Missing userName" );
        return NULL;
    }
    if (!userSecret) {
        err( "Missing userSecret" );
        return NULL;
    }

    SpectreUserKey *userKey = memcpy( malloc( sizeof( SpectreUserKey ) ),
            &(SpectreUserKey){ .algorithm = algorithmVersion }, sizeof( SpectreUserKey ) );

    bool success = false;
    switch (algorithmVersion) {
        case SpectreAlgorithmV0:
            success = spectre_user_key_v0( userKey, userName, userSecret );
            break;
        case SpectreAlgorithmV1:
            success = spectre_user_key_v1( userKey, userName, userSecret );
            break;
        case SpectreAlgorithmV2:
            success = spectre_user_key_v2( userKey, userName, userSecret );
            break;
        case SpectreAlgorithmV3:
            success = spectre_user_key_v3( userKey, userName, userSecret );
            break;
        default:
            err( "Unsupported version: %d", algorithmVersion );
    }

    if (success)
        return userKey;

    spectre_free( &userKey, sizeof( SpectreUserKey ) );
    return NULL;
}

const SpectreSiteKey *spectre_site_key(
        const SpectreUserKey *userKey, const char *siteName,
        const SpectreCounter keyCounter, const SpectreKeyPurpose keyPurpose, const char *keyContext) {

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

    trc( "-- spectre_site_key (algorithm: %u)", userKey->algorithm );
    trc( "siteName: %s", siteName );
    trc( "keyCounter: %d", keyCounter );
    trc( "keyPurpose: %d (%s)", keyPurpose, spectre_purpose_name( keyPurpose ) );
    trc( "keyContext: %s", keyContext );

    SpectreSiteKey *siteKey = memcpy( malloc( sizeof( SpectreSiteKey ) ),
            &(SpectreSiteKey){ .algorithm = userKey->algorithm }, sizeof( SpectreSiteKey ) );

    bool success = false;
    switch (userKey->algorithm) {
        case SpectreAlgorithmV0:
            success = spectre_site_key_v0( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case SpectreAlgorithmV1:
            success = spectre_site_key_v1( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case SpectreAlgorithmV2:
            success = spectre_site_key_v2( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case SpectreAlgorithmV3:
            success = spectre_site_key_v3( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        default:
            err( "Unsupported version: %d", userKey->algorithm );
    }

    if (success)
        return siteKey;

    spectre_free( &siteKey, sizeof( SpectreSiteKey ) );
    return NULL;
}

const char *spectre_site_result(
        const SpectreUserKey *userKey, const char *siteName,
        const SpectreResultType resultType, const char *resultParam,
        const SpectreCounter keyCounter, const SpectreKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }

    const SpectreSiteKey *siteKey = spectre_site_key( userKey, siteName, keyCounter, keyPurpose, keyContext );
    if (!siteKey) {
        err( "Missing siteKey" );
        return NULL;
    }

    trc( "-- spectre_site_result (algorithm: %u)", userKey->algorithm );
    trc( "resultType: %d (%s)", resultType, spectre_type_short_name( resultType ) );
    trc( "resultParam: %s", resultParam );

    const char *result = NULL;
    if (resultType == SpectreResultNone) {
        result = NULL;
    }
    else if (resultType & SpectreResultClassTemplate) {
        switch (userKey->algorithm) {
            case SpectreAlgorithmV0:
                result = spectre_site_template_password_v0( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV1:
                result = spectre_site_template_password_v1( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV2:
                result = spectre_site_template_password_v2( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV3:
                result = spectre_site_template_password_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }
    else if (resultType & SpectreResultClassStateful) {
        switch (userKey->algorithm) {
            case SpectreAlgorithmV0:
                result = spectre_site_crypted_password_v0( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV1:
                result = spectre_site_crypted_password_v1( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV2:
                result = spectre_site_crypted_password_v2( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV3:
                result = spectre_site_crypted_password_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }
    else if (resultType & SpectreResultClassDerive) {
        switch (userKey->algorithm) {
            case SpectreAlgorithmV0:
                result = spectre_site_derived_password_v0( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV1:
                result = spectre_site_derived_password_v1( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV2:
                result = spectre_site_derived_password_v2( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV3:
                result = spectre_site_derived_password_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }
    else {
        err( "Unsupported password type: %d", resultType );
    }

    spectre_free( &siteKey, sizeof( SpectreSiteKey ) );
    return result;
}

const char *spectre_site_state(
        const SpectreUserKey *userKey, const char *siteName,
        const SpectreResultType resultType, const char *resultParam,
        const SpectreCounter keyCounter, const SpectreKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }
    if (!resultParam) {
        err( "Missing resultParam" );
        return NULL;
    }

    const SpectreSiteKey *siteKey = spectre_site_key( userKey, siteName, keyCounter, keyPurpose, keyContext );
    if (!siteKey) {
        err( "Missing siteKey" );
        return NULL;
    }

    trc( "-- spectre_site_state (algorithm: %u)", userKey->algorithm );
    trc( "resultType: %d (%s)", resultType, spectre_type_short_name( resultType ) );
    trc( "resultParam: %zu bytes = %s", resultParam? strlen( resultParam ): 0, resultParam );

    const char *result = NULL;
    if (resultType == SpectreResultNone) {
        result = NULL;
    }
    else {
        switch (userKey->algorithm) {
            case SpectreAlgorithmV0:
                result = spectre_site_state_v0( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV1:
                result = spectre_site_state_v1( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV2:
                result = spectre_site_state_v2( userKey, siteKey, resultType, resultParam );
                break;
            case SpectreAlgorithmV3:
                result = spectre_site_state_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }

    spectre_free( &siteKey, sizeof( SpectreSiteKey ) );
    return result;
}

static const char *spectre_identicon_leftArms[] = { "╔", "╚", "╰", "═" };
static const char *spectre_identicon_bodies[] = { "█", "░", "▒", "▓", "☺", "☻" };
static const char *spectre_identicon_rightArms[] = { "╗", "╝", "╯", "═" };
static const char *spectre_identicon_accessories[] = {
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘", "☢", "☣",
        "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟",
        "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌"
};

const SpectreIdenticon spectre_identicon(
        const char *userName, const char *userSecret) {

    uint8_t seed[32] = { 0 };
    if (userName && strlen( userName ) && userSecret && strlen( userSecret ))
        if (!spectre_hash_hmac_sha256( seed,
                (const uint8_t *)userSecret, strlen( userSecret ),
                (const uint8_t *)userName, strlen( userName ) )) {
            spectre_zero( &seed, sizeof( seed ) );
            return SpectreIdenticonUnset;
        }

    SpectreIdenticon identicon = {
            .leftArm = spectre_identicon_leftArms[seed[0] % (sizeof( spectre_identicon_leftArms ) / sizeof( *spectre_identicon_leftArms ))],
            .body = spectre_identicon_bodies[seed[1] % (sizeof( spectre_identicon_bodies ) / sizeof( *spectre_identicon_bodies ))],
            .rightArm = spectre_identicon_rightArms[seed[2] % (sizeof( spectre_identicon_rightArms ) / sizeof( *spectre_identicon_rightArms ))],
            .accessory = spectre_identicon_accessories[seed[3] % (sizeof( spectre_identicon_accessories ) / sizeof( *spectre_identicon_accessories ))],
            .color = (SpectreIdenticonColor)(seed[4] % (SpectreIdenticonColorLast - SpectreIdenticonColorFirst + 1) + SpectreIdenticonColorFirst),
    };
    spectre_zero( &seed, sizeof( seed ) );

    return identicon;
}

const char *spectre_identicon_encode(
        const SpectreIdenticon identicon) {

    if (identicon.color == SpectreIdenticonColorUnset)
        return NULL;

    return spectre_str( "%hhu:%s%s%s%s",
            identicon.color, identicon.leftArm, identicon.body, identicon.rightArm, identicon.accessory );
}

const SpectreIdenticon spectre_identicon_encoded(
        const char *encoding) {

    SpectreIdenticon identicon = SpectreIdenticonUnset;
    if (!encoding || !strlen( encoding ))
        return identicon;

    char *string = calloc( strlen( encoding ), sizeof( *string ) ), *parser = string;
    const char *leftArm = NULL, *body = NULL, *rightArm = NULL, *accessory = NULL;
    unsigned int color;

    if (string && sscanf( encoding, "%u:%s", &color, string ) == 2) {
        if (*parser && color)
            for (unsigned int s = 0; s < sizeof( spectre_identicon_leftArms ) / sizeof( *spectre_identicon_leftArms ); ++s) {
                const char *limb = spectre_identicon_leftArms[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    leftArm = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && leftArm)
            for (unsigned int s = 0; s < sizeof( spectre_identicon_bodies ) / sizeof( *spectre_identicon_bodies ); ++s) {
                const char *limb = spectre_identicon_bodies[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    body = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && body)
            for (unsigned int s = 0; s < sizeof( spectre_identicon_rightArms ) / sizeof( *spectre_identicon_rightArms ); ++s) {
                const char *limb = spectre_identicon_rightArms[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    rightArm = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && rightArm)
            for (unsigned int s = 0; s < sizeof( spectre_identicon_accessories ) / sizeof( *spectre_identicon_accessories ); ++s) {
                const char *limb = spectre_identicon_accessories[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    accessory = limb;
                    break;
                }
            }
        if (leftArm && body && rightArm && color >= SpectreIdenticonColorFirst && color <= SpectreIdenticonColorLast)
            identicon = (SpectreIdenticon){
                    .leftArm = leftArm,
                    .body = body,
                    .rightArm = rightArm,
                    .accessory = accessory,
                    .color = (SpectreIdenticonColor)color,
            };
    }

    spectre_free_string( &string );
    return identicon;
}
