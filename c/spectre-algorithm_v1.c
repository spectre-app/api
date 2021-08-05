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

#include "spectre-algorithm_v1.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
SPECTRE_LIBS_END

#define Spectre_N                32768LU
#define Spectre_r                8U
#define Spectre_p                2U
#define Spectre_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool spectre_user_key_v1(
        const SpectreUserKey *userKey, const char *userName, const char *userSecret) {

    return spectre_user_key_v0( userKey, userName, userSecret );
}

bool spectre_site_key_v1(
        const SpectreSiteKey *siteKey, const SpectreUserKey *userKey, const char *siteName,
        SpectreCounter keyCounter, SpectreKeyPurpose keyPurpose, const char *keyContext) {

    return spectre_site_key_v0( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
}

const char *spectre_site_template_password_v1(
        __unused const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, __unused const char *resultParam) {

    // Determine the template.
    uint8_t seedByte = siteKey->bytes[0];
    const char *template = spectre_type_template( resultType, seedByte );
    trc( "template: %u => %s", seedByte, template );
    if (!template)
        return NULL;
    if (strlen( template ) > sizeof( siteKey->bytes ) - 1) {
        err( "Template too long for password seed: %zu", strlen( template ) );
        return NULL;
    }

    // Encode the password from the seed using the template.
    char *const sitePassword = calloc( strlen( template ) + 1, sizeof( char ) );
    for (size_t c = 0; c < strlen( template ); ++c) {
        seedByte = siteKey->bytes[c + 1];
        sitePassword[c] = spectre_class_character( template[c], seedByte );
        trc( "  - class: %c, index: %3u (0x%.2hhX) => character: %c",
                template[c], seedByte, seedByte, sitePassword[c] );
    }
    trc( "  => password: %s", sitePassword );

    return sitePassword;
}

const char *spectre_site_crypted_password_v1(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *cipherText) {

    return spectre_site_crypted_password_v0( userKey, siteKey, resultType, cipherText );
}

const char *spectre_site_derived_password_v1(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam) {

    return spectre_site_derived_password_v0( userKey, siteKey, resultType, resultParam );
}

const char *spectre_site_state_v1(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *state) {

    return spectre_site_state_v0( userKey, siteKey, resultType, state );
}
