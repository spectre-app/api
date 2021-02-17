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
bool mpw_user_key_v3(
        const MPUserKey *userKey, const char *userName, const char *userSecret) {

    const char *keyScope = mpw_purpose_scope( MPKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the user key salt.
    trc( "userKeySalt: keyScope=%s | #userName=%s | userName=%s",
            keyScope, mpw_hex_l( (uint32_t)strlen( userName ), (char[9]){ 0 } ), userName );
    size_t userKeySaltSize = 0;
    uint8_t *userKeySalt = NULL;
    if (!(mpw_buf_push( &userKeySalt, &userKeySaltSize, keyScope ) &&
          mpw_buf_push( &userKeySalt, &userKeySaltSize, (uint32_t)strlen( userName ) ) &&
          mpw_buf_push( &userKeySalt, &userKeySaltSize, userName )) || !userKeySalt) {
        mpw_free( &userKeySalt, userKeySaltSize );
        err( "Could not allocate user key salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => userKeySalt.id: %s", mpw_id_buf( userKeySalt, userKeySaltSize ).hex );

    // Calculate the user key.
    trc( "userKey: scrypt( userSecret, userKeySalt, N=%lu, r=%u, p=%u )", MP_N, MP_r, MP_p );
    bool success = mpw_kdf_scrypt( (uint8_t *)userKey->bytes, sizeof( userKey->bytes ),
            (uint8_t *)userSecret, strlen( userSecret ), userKeySalt, userKeySaltSize, MP_N, MP_r, MP_p );
    mpw_free( &userKeySalt, userKeySaltSize );

    if (!success)
        err( "Could not derive user key: %s", strerror( errno ) );
    else {
        MPKeyID keyID = mpw_id_buf( userKey->bytes, sizeof( userKey->bytes ) );
        memcpy( (MPKeyID *)&userKey->keyID, &keyID, sizeof( userKey->keyID ) );
        trc( "  => userKey.id: %s (algorithm: %d:3)", userKey->keyID.hex, userKey->algorithm );
    }
    return success;
}

bool mpw_site_key_v3(
        const MPSiteKey *siteKey, const MPUserKey *userKey, const char *siteName,
        MPCounterValue keyCounter, MPKeyPurpose keyPurpose, const char *keyContext) {

    return mpw_site_key_v2( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
}

const char *mpw_site_template_password_v3(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *resultParam) {

    return mpw_site_template_password_v2( userKey, siteKey, resultType, resultParam );
}

const char *mpw_site_crypted_password_v3(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *cipherText) {

    return mpw_site_crypted_password_v2( userKey, siteKey, resultType, cipherText );
}

const char *mpw_site_derived_password_v3(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *resultParam) {

    return mpw_site_derived_password_v2( userKey, siteKey, resultType, resultParam );
}

const char *mpw_site_state_v3(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *state) {

    return mpw_site_state_v2( userKey, siteKey, resultType, state );
}
