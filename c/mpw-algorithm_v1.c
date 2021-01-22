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

#include "mpw-algorithm_v1.h"
#include "mpw-util.h"

MP_LIBS_BEGIN
#include <string.h>
MP_LIBS_END

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U
#define MP_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool mpw_master_key_v1(
        const MPMasterKey *masterKey, const char *fullName, const char *masterPassword) {

    return mpw_master_key_v0( masterKey, fullName, masterPassword );
}

bool mpw_service_key_v1(
        const MPServiceKey *serviceKey, const MPMasterKey *masterKey, const char *serviceName,
        MPCounterValue keyCounter, MPKeyPurpose keyPurpose, const char *keyContext) {

    return mpw_service_key_v0( serviceKey, masterKey, serviceName, keyCounter, keyPurpose, keyContext );
}

const char *mpw_service_template_password_v1(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *resultParam) {

    // Determine the template.
    uint8_t seedByte = serviceKey->bytes[0];
    const char *template = mpw_type_template( resultType, seedByte );
    trc( "template: %u => %s", seedByte, template );
    if (!template)
        return NULL;
    if (strlen( template ) > sizeof( serviceKey->bytes )) {
        err( "Template too long for password seed: %zu", strlen( template ) );
        return NULL;
    }

    // Encode the password from the seed using the template.
    char *const servicePassword = calloc( strlen( template ) + 1, sizeof( char ) );
    for (size_t c = 0; c < strlen( template ); ++c) {
        seedByte = serviceKey->bytes[c + 1];
        servicePassword[c] = mpw_class_character( template[c], seedByte );
        trc( "  - class: %c, index: %3u (0x%.2hhX) => character: %c",
                template[c], seedByte, seedByte, servicePassword[c] );
    }
    trc( "  => password: %s", servicePassword );

    return servicePassword;
}

const char *mpw_service_crypted_password_v1(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *cipherText) {

    return mpw_service_crypted_password_v0( masterKey, serviceKey, resultType, cipherText );
}

const char *mpw_service_derived_password_v1(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *resultParam) {

    return mpw_service_derived_password_v0( masterKey, serviceKey, resultType, resultParam );
}

const char *mpw_service_state_v1(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *state) {

    return mpw_service_state_v0( masterKey, serviceKey, resultType, state );
}
