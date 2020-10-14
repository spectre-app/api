//==============================================================================
// This file is part of Master Password.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// Master Password is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Master Password is distributed in the hope that it will be useful,
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

const MPMasterKey *mpw_master_key(
        const char *fullName, const char *masterPassword, const MPAlgorithmVersion algorithmVersion) {

    if (fullName && !strlen( fullName ))
        fullName = NULL;
    if (masterPassword && !strlen( masterPassword ))
        masterPassword = NULL;

    trc( "-- mpw_master_key (algorithm: %u)", algorithmVersion );
    trc( "fullName: %s", fullName );
    trc( "masterPassword.id: %s", masterPassword? mpw_id_buf( (uint8_t *)masterPassword, strlen( masterPassword ) ).hex: NULL );
    if (!fullName) {
        err( "Missing fullName" );
        return NULL;
    }
    if (!masterPassword) {
        err( "Missing masterPassword" );
        return NULL;
    }

    MPMasterKey *masterKey = memcpy( malloc( sizeof( MPMasterKey ) ),
            &(MPMasterKey){ .algorithm = algorithmVersion }, sizeof( MPMasterKey ) );

    bool success = false;
    switch (algorithmVersion) {
        case MPAlgorithmVersionV0:
            success = mpw_master_key_v0( masterKey, fullName, masterPassword );
            break;
        case MPAlgorithmVersionV1:
            success = mpw_master_key_v1( masterKey, fullName, masterPassword );
            break;
        case MPAlgorithmVersionV2:
            success = mpw_master_key_v2( masterKey, fullName, masterPassword );
            break;
        case MPAlgorithmVersionV3:
            success = mpw_master_key_v3( masterKey, fullName, masterPassword );
            break;
        default:
            err( "Unsupported version: %d", algorithmVersion );
    }

    if (success)
        return masterKey;

    mpw_free( &masterKey, sizeof( MPMasterKey ) );
    return NULL;
}

const MPServiceKey *mpw_service_key(
        const MPMasterKey *masterKey, const char *serviceName,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (!masterKey) {
        err( "Missing masterKey" );
        return NULL;
    }
    if (!serviceName) {
        err( "Missing serviceName" );
        return NULL;
    }

    trc( "-- mpw_service_key (algorithm: %u)", masterKey->algorithm );
    trc( "serviceName: %s", serviceName );
    trc( "keyCounter: %d", keyCounter );
    trc( "keyPurpose: %d (%s)", keyPurpose, mpw_purpose_name( keyPurpose ) );
    trc( "keyContext: %s", keyContext );

    MPServiceKey *serviceKey = memcpy( malloc( sizeof( MPServiceKey ) ),
            &(MPServiceKey){ .algorithm = masterKey->algorithm }, sizeof( MPServiceKey ) );

    bool success = false;
    switch (masterKey->algorithm) {
        case MPAlgorithmVersionV0:
            success = mpw_service_key_v0( serviceKey, masterKey, serviceName, keyCounter, keyPurpose, keyContext );
            break;
        case MPAlgorithmVersionV1:
            success = mpw_service_key_v1( serviceKey, masterKey, serviceName, keyCounter, keyPurpose, keyContext );
            break;
        case MPAlgorithmVersionV2:
            success = mpw_service_key_v2( serviceKey, masterKey, serviceName, keyCounter, keyPurpose, keyContext );
            break;
        case MPAlgorithmVersionV3:
            success = mpw_service_key_v3( serviceKey, masterKey, serviceName, keyCounter, keyPurpose, keyContext );
            break;
        default:
            err( "Unsupported version: %d", masterKey->algorithm );
    }

    if (success)
        return serviceKey;

    mpw_free( &serviceKey, sizeof( MPServiceKey ) );
    return NULL;
}

const char *mpw_service_result(
        const MPMasterKey *masterKey, const char *serviceName,
        const MPResultType resultType, const char *resultParam,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!masterKey) {
        err( "Missing masterKey" );
        return NULL;
    }

    const MPServiceKey *serviceKey = mpw_service_key( masterKey, serviceName, keyCounter, keyPurpose, keyContext );
    if (!serviceKey) {
        err( "Missing serviceKey" );
        return NULL;
    }

    trc( "-- mpw_service_result (algorithm: %u)", masterKey->algorithm );
    trc( "resultType: %d (%s)", resultType, mpw_type_short_name( resultType ) );
    trc( "resultParam: %s", resultParam );

    if (resultType == MPResultTypeNone) {
        return NULL;
    }
    else if (resultType & MPResultTypeClassTemplate) {
        switch (masterKey->algorithm) {
            case MPAlgorithmVersionV0:
                return mpw_service_template_password_v0( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV1:
                return mpw_service_template_password_v1( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV2:
                return mpw_service_template_password_v2( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV3:
                return mpw_service_template_password_v3( masterKey, serviceKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d", masterKey->algorithm );
                return NULL;
        }
    }
    else if (resultType & MPResultTypeClassStateful) {
        switch (masterKey->algorithm) {
            case MPAlgorithmVersionV0:
                return mpw_service_crypted_password_v0( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV1:
                return mpw_service_crypted_password_v1( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV2:
                return mpw_service_crypted_password_v2( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV3:
                return mpw_service_crypted_password_v3( masterKey, serviceKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d", masterKey->algorithm );
                return NULL;
        }
    }
    else if (resultType & MPResultTypeClassDerive) {
        switch (masterKey->algorithm) {
            case MPAlgorithmVersionV0:
                return mpw_service_derived_password_v0( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV1:
                return mpw_service_derived_password_v1( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV2:
                return mpw_service_derived_password_v2( masterKey, serviceKey, resultType, resultParam );
            case MPAlgorithmVersionV3:
                return mpw_service_derived_password_v3( masterKey, serviceKey, resultType, resultParam );
            default:
                err( "Unsupported version: %d", masterKey->algorithm );
                return NULL;
        }
    }
    else {
        err( "Unsupported password type: %d", resultType );
    }

    return NULL;
}

const char *mpw_service_state(
        const MPMasterKey *masterKey, const char *serviceName,
        const MPResultType resultType, const char *resultParam,
        const MPCounterValue keyCounter, const MPKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!masterKey) {
        err( "Missing masterKey" );
        return NULL;
    }

    const MPServiceKey *serviceKey = mpw_service_key( masterKey, serviceName, keyCounter, keyPurpose, keyContext );
    if (!serviceKey) {
        err( "Missing serviceKey" );
        return NULL;
    }
    if (!resultParam) {
        err( "Missing resultParam" );
        return NULL;
    }

    trc( "-- mpw_service_state (algorithm: %u)", masterKey->algorithm );
    trc( "resultType: %d (%s)", resultType, mpw_type_short_name( resultType ) );
    trc( "resultParam: %zu bytes = %s", resultParam? strlen( resultParam ): 0, resultParam );

    if (resultType == MPResultTypeNone) {
        return NULL;
    }

    switch (masterKey->algorithm) {
        case MPAlgorithmVersionV0:
            return mpw_service_state_v0( masterKey, serviceKey, resultType, resultParam );
        case MPAlgorithmVersionV1:
            return mpw_service_state_v1( masterKey, serviceKey, resultType, resultParam );
        case MPAlgorithmVersionV2:
            return mpw_service_state_v2( masterKey, serviceKey, resultType, resultParam );
        case MPAlgorithmVersionV3:
            return mpw_service_state_v3( masterKey, serviceKey, resultType, resultParam );
        default:
            err( "Unsupported version: %d", masterKey->algorithm );
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
        const char *fullName, const char *masterPassword) {

    uint8_t seed[32] = { 0 };
    if (fullName && strlen( fullName ) && masterPassword && strlen( masterPassword ))
        if (!mpw_hash_hmac_sha256( seed,
                (const uint8_t *)masterPassword, strlen( masterPassword ),
                (const uint8_t *)fullName, strlen( fullName ) )) {
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
