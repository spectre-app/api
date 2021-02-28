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

#include "spectre-algorithm_v2.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
#include <errno.h>
#include <time.h>
SPECTRE_LIBS_END

#define Spectre_N                32768LU
#define Spectre_r                8U
#define Spectre_p                2U
#define Spectre_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool spectre_user_key_v2(
        const SpectreUserKey *userKey, const char *userName, const char *userSecret) {

    return spectre_user_key_v1( userKey, userName, userSecret );
}

bool spectre_site_key_v2(
        const SpectreSiteKey *siteKey, const SpectreUserKey *userKey, const char *siteName,
        SpectreCounter keyCounter, SpectreKeyPurpose keyPurpose, const char *keyContext) {

    const char *keyScope = spectre_purpose_scope( keyPurpose );
    trc( "keyScope: %s", keyScope );

    // OTP counter value.
    if (keyCounter == SpectreCounterTOTP)
        keyCounter = ((SpectreCounter)time( NULL ) / Spectre_otp_window) * Spectre_otp_window;

    // Calculate the site seed.
    trc( "siteSalt: keyScope=%s | #siteName=%s | siteName=%s | keyCounter=%s | #keyContext=%s | keyContext=%s",
            keyScope, spectre_hex_l( (uint32_t)strlen( siteName ), (char[9]){ 0 } ), siteName, spectre_hex_l( keyCounter, (char[9]){ 0 } ),
            keyContext? spectre_hex_l( (uint32_t)strlen( keyContext ), (char[9]){ 0 } ): NULL, keyContext );
    size_t siteSaltSize = 0;
    uint8_t *siteSalt = NULL;
    if (!(spectre_buf_push( &siteSalt, &siteSaltSize, keyScope ) &&
          spectre_buf_push( &siteSalt, &siteSaltSize, (uint32_t)strlen( siteName ) ) &&
          spectre_buf_push( &siteSalt, &siteSaltSize, siteName ) &&
          spectre_buf_push( &siteSalt, &siteSaltSize, (uint32_t)keyCounter ) &&
          (!keyContext? true:
           spectre_buf_push( &siteSalt, &siteSaltSize, (uint32_t)strlen( keyContext ) ) &&
           spectre_buf_push( &siteSalt, &siteSaltSize, keyContext ))) || !siteSalt) {
        err( "Could not allocate site salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => siteSalt.id: %s", spectre_id_buf( siteSalt, siteSaltSize ).hex );

    trc( "siteKey: hmac-sha256( userKey.id=%s, siteSalt )", userKey->keyID.hex );
    bool success = spectre_hash_hmac_sha256( (uint8_t *)siteKey->bytes,
            userKey->bytes, sizeof( userKey->bytes ), siteSalt, siteSaltSize );
    spectre_free( &siteSalt, siteSaltSize );

    if (!success)
        err( "Could not derive site key: %s", strerror( errno ) );
    else {
        SpectreKeyID keyID = spectre_id_buf( siteKey->bytes, sizeof( siteKey->bytes ) );
        memcpy( (SpectreKeyID *)&siteKey->keyID, &keyID, sizeof( siteKey->keyID ) );
        trc( "  => siteKey.id: %s (algorithm: %d:2)", siteKey->keyID.hex, siteKey->algorithm );
    }
    return success;
}

const char *spectre_site_template_password_v2(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam) {

    return spectre_site_template_password_v1( userKey, siteKey, resultType, resultParam );
}

const char *spectre_site_crypted_password_v2(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *cipherText) {

    return spectre_site_crypted_password_v1( userKey, siteKey, resultType, cipherText );
}

const char *spectre_site_derived_password_v2(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam) {

    return spectre_site_derived_password_v1( userKey, siteKey, resultType, resultParam );
}

const char *spectre_site_state_v2(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *state) {

    return spectre_site_state_v1( userKey, siteKey, resultType, state );
}
