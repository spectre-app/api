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

#include "spectre-algorithm_v1.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
SPECTRE_LIBS_END

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U
#define MP_otp_window       5 * 60 /* s */

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
    if (strlen( template ) > sizeof( siteKey->bytes )) {
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
