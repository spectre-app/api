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

#include "spectre-algorithm_v3.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
#include <errno.h>
SPECTRE_LIBS_END

#define Spectre_N                32768LU
#define Spectre_r                8U
#define Spectre_p                2U
#define Spectre_otp_window       5 * 60 /* s */

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
    trc( "userKey: scrypt( userSecret, userKeySalt, N=%lu, r=%u, p=%u )", Spectre_N, Spectre_r, Spectre_p );
    bool success = spectre_kdf_scrypt( (uint8_t *)userKey->bytes, sizeof( userKey->bytes ),
            (uint8_t *)userSecret, strlen( userSecret ), userKeySalt, userKeySaltSize, Spectre_N, Spectre_r, Spectre_p );
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
