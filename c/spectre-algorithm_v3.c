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

#include "spectre-algorithm_v3.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
#include <errno.h>
SPECTRE_LIBS_END

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U
#define MP_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool spectre_user_key_v3(
        const SpectreUserKey *userKey, const char *userName, const char *userSecret) {

    const char *keyScope = spectre_purpose_scope( SpectreKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the user key salt.
    trc( "userKeySalt: keyScope=%s | #userName=%s | userName=%s",
            keyScope, spectre_hex_l( (uint32_t)strlen( userName ), (char[9]){ 0 } ), userName );
    size_t userKeySaltSize = 0;
    uint8_t *userKeySalt = NULL;
    if (!(spectre_buf_push( &userKeySalt, &userKeySaltSize, keyScope ) &&
          spectre_buf_push( &userKeySalt, &userKeySaltSize, (uint32_t)strlen( userName ) ) &&
          spectre_buf_push( &userKeySalt, &userKeySaltSize, userName )) || !userKeySalt) {
        spectre_free( &userKeySalt, userKeySaltSize );
        err( "Could not allocate user key salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => userKeySalt.id: %s", spectre_id_buf( userKeySalt, userKeySaltSize ).hex );

    // Calculate the user key.
    trc( "userKey: scrypt( userSecret, userKeySalt, N=%lu, r=%u, p=%u )", MP_N, MP_r, MP_p );
    bool success = spectre_kdf_scrypt( (uint8_t *)userKey->bytes, sizeof( userKey->bytes ),
            (uint8_t *)userSecret, strlen( userSecret ), userKeySalt, userKeySaltSize, MP_N, MP_r, MP_p );
    spectre_free( &userKeySalt, userKeySaltSize );

    if (!success)
        err( "Could not derive user key: %s", strerror( errno ) );
    else {
        SpectreKeyID keyID = spectre_id_buf( userKey->bytes, sizeof( userKey->bytes ) );
        memcpy( (SpectreKeyID *)&userKey->keyID, &keyID, sizeof( userKey->keyID ) );
        trc( "  => userKey.id: %s (algorithm: %d:3)", userKey->keyID.hex, userKey->algorithm );
    }
    return success;
}

bool spectre_site_key_v3(
        const SpectreSiteKey *siteKey, const SpectreUserKey *userKey, const char *siteName,
        SpectreCounter keyCounter, SpectreKeyPurpose keyPurpose, const char *keyContext) {

    return spectre_site_key_v2( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
}

const char *spectre_site_template_password_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam) {

    return spectre_site_template_password_v2( userKey, siteKey, resultType, resultParam );
}

const char *spectre_site_crypted_password_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *cipherText) {

    return spectre_site_crypted_password_v2( userKey, siteKey, resultType, cipherText );
}

const char *spectre_site_derived_password_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam) {

    return spectre_site_derived_password_v2( userKey, siteKey, resultType, resultParam );
}

const char *spectre_site_state_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *state) {

    return spectre_site_state_v2( userKey, siteKey, resultType, state );
}
