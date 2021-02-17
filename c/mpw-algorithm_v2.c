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

#include "mpw-algorithm_v2.h"
#include "mpw-util.h"

MP_LIBS_BEGIN
#include <string.h>
#include <errno.h>
#include <time.h>
MP_LIBS_END

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U
#define MP_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool mpw_user_key_v2(
        const MPUserKey *userKey, const char *userName, const char *userSecret) {

    return mpw_user_key_v1( userKey, userName, userSecret );
}

bool mpw_site_key_v2(
        const MPSiteKey *siteKey, const MPUserKey *userKey, const char *siteName,
        MPCounterValue keyCounter, MPKeyPurpose keyPurpose, const char *keyContext) {

    const char *keyScope = mpw_purpose_scope( keyPurpose );
    trc( "keyScope: %s", keyScope );

    // OTP counter value.
    if (keyCounter == MPCounterValueTOTP)
        keyCounter = ((MPCounterValue)time( NULL ) / MP_otp_window) * MP_otp_window;

    // Calculate the site seed.
    trc( "siteSalt: keyScope=%s | #siteName=%s | siteName=%s | keyCounter=%s | #keyContext=%s | keyContext=%s",
            keyScope, mpw_hex_l( (uint32_t)strlen( siteName ), (char[9]){ 0 } ), siteName, mpw_hex_l( keyCounter, (char[9]){ 0 } ),
            keyContext? mpw_hex_l( (uint32_t)strlen( keyContext ), (char[9]){ 0 } ): NULL, keyContext );
    size_t siteSaltSize = 0;
    uint8_t *siteSalt = NULL;
    if (!(mpw_buf_push( &siteSalt, &siteSaltSize, keyScope ) &&
          mpw_buf_push( &siteSalt, &siteSaltSize, (uint32_t)strlen( siteName ) ) &&
          mpw_buf_push( &siteSalt, &siteSaltSize, siteName ) &&
          mpw_buf_push( &siteSalt, &siteSaltSize, (uint32_t)keyCounter ) &&
          (!keyContext? true:
           mpw_buf_push( &siteSalt, &siteSaltSize, (uint32_t)strlen( keyContext ) ) &&
           mpw_buf_push( &siteSalt, &siteSaltSize, keyContext ))) || !siteSalt) {
        err( "Could not allocate site salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => siteSalt.id: %s", mpw_id_buf( siteSalt, siteSaltSize ).hex );

    trc( "siteKey: hmac-sha256( userKey.id=%s, siteSalt )", userKey->keyID.hex );
    bool success = mpw_hash_hmac_sha256( (uint8_t *)siteKey->bytes,
            userKey->bytes, sizeof( userKey->bytes ), siteSalt, siteSaltSize );
    mpw_free( &siteSalt, siteSaltSize );

    if (!success)
        err( "Could not derive site key: %s", strerror( errno ) );
    else {
        MPKeyID keyID = mpw_id_buf( siteKey->bytes, sizeof( siteKey->bytes ) );
        memcpy( (MPKeyID *)&siteKey->keyID, &keyID, sizeof( siteKey->keyID ) );
        trc( "  => siteKey.id: %s (algorithm: %d:2)", siteKey->keyID.hex, siteKey->algorithm );
    }
    return success;
}

const char *mpw_site_template_password_v2(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *resultParam) {

    return mpw_site_template_password_v1( userKey, siteKey, resultType, resultParam );
}

const char *mpw_site_crypted_password_v2(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *cipherText) {

    return mpw_site_crypted_password_v1( userKey, siteKey, resultType, cipherText );
}

const char *mpw_site_derived_password_v2(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *resultParam) {

    return mpw_site_derived_password_v1( userKey, siteKey, resultType, resultParam );
}

const char *mpw_site_state_v2(
        const MPUserKey *userKey, const MPSiteKey *siteKey, MPResultType resultType, const char *state) {

    return mpw_site_state_v1( userKey, siteKey, resultType, state );
}
