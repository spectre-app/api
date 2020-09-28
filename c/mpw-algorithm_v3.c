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

#include "mpw-algorithm_v3.h"
#include "mpw-util.h"

MP_LIBS_BEGIN
#include <string.h>
#include <errno.h>
MP_LIBS_END

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U
#define MP_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool mpw_master_key_v3(
        const MPMasterKey *masterKey, const char *fullName, const char *masterPassword) {

    const char *keyScope = mpw_purpose_scope( MPKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the master key salt.
    trc( "masterKeySalt: keyScope=%s | #fullName=%s | fullName=%s",
            keyScope, mpw_hex_l( (uint32_t)strlen( fullName ), (char[9]){ 0 } ), fullName );
    size_t masterKeySaltSize = 0;
    uint8_t *masterKeySalt = NULL;
    if (!(mpw_push_string( &masterKeySalt, &masterKeySaltSize, keyScope ) &&
          mpw_push_int( &masterKeySalt, &masterKeySaltSize, (uint32_t)strlen( fullName ) ) &&
          mpw_push_string( &masterKeySalt, &masterKeySaltSize, fullName )) || !masterKeySalt) {
        mpw_free( &masterKeySalt, masterKeySaltSize );
        err( "Could not allocate master key salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => masterKeySalt.id: %s", mpw_id_buf( masterKeySalt, masterKeySaltSize ).hex );

    // Calculate the master key.
    trc( "masterKey: scrypt( masterPassword, masterKeySalt, N=%lu, r=%u, p=%u )", MP_N, MP_r, MP_p );
    bool success = mpw_kdf_scrypt( (uint8_t *)masterKey->bytes, sizeof( masterKey->bytes ),
            (uint8_t *)masterPassword, strlen( masterPassword ), masterKeySalt, masterKeySaltSize, MP_N, MP_r, MP_p );
    mpw_free( &masterKeySalt, masterKeySaltSize );

    if (!success)
        err( "Could not derive master key: %s", strerror( errno ) );
    else {
        MPKeyID keyID = mpw_id_buf( masterKey->bytes, sizeof( masterKey->bytes ) );
        memcpy( (MPKeyID *)&masterKey->keyID, &keyID, sizeof( masterKey->keyID ) );
        trc( "  => masterKey.id: %s (algorithm: %d:3)", masterKey->keyID.hex, masterKey->algorithm );
    }
    return success;
}

bool mpw_service_key_v3(
        const MPServiceKey *serviceKey, const MPMasterKey *masterKey, const char *serviceName, MPCounterValue keyCounter,
        MPKeyPurpose keyPurpose, const char *keyContext) {

    return mpw_service_key_v2( serviceKey, masterKey, serviceName, keyCounter, keyPurpose, keyContext );
}

const char *mpw_service_template_password_v3(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *resultParam) {

    return mpw_service_template_password_v2( masterKey, serviceKey, resultType, resultParam );
}

const char *mpw_service_crypted_password_v3(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *cipherText) {

    return mpw_service_crypted_password_v2( masterKey, serviceKey, resultType, cipherText );
}

const char *mpw_service_derived_password_v3(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *resultParam) {

    return mpw_service_derived_password_v2( masterKey, serviceKey, resultType, resultParam );
}

const char *mpw_service_state_v3(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *state) {

    return mpw_service_state_v2( masterKey, serviceKey, resultType, state );
}
