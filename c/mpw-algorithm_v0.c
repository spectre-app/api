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

#include "mpw-algorithm_v0.h"
#include "mpw-util.h"
#include "base64.h"

MP_LIBS_BEGIN
#include <string.h>
#include <errno.h>
#include <time.h>
MP_LIBS_END

#define MP_N                32768LU
#define MP_r                8U
#define MP_p                2U
#define MP_otp_window       5 * 60 /* s */

// Algorithm version helpers.
const char *mpw_type_template_v0(const MPResultType type, uint16_t templateIndex) {

    size_t count = 0;
    const char **templates = mpw_type_templates( type, &count );
    char const *template = templates && count? templates[templateIndex % count]: NULL;
    free( templates );

    return template;
}

const char mpw_class_character_v0(char characterClass, uint16_t classIndex) {

    const char *classCharacters = mpw_class_characters( characterClass );
    if (!classCharacters)
        return '\0';

    return classCharacters[classIndex % strlen( classCharacters )];
}

// Algorithm version overrides.
bool mpw_master_key_v0(
        const MPMasterKey *masterKey, const char *fullName, const char *masterPassword) {

    const char *keyScope = mpw_purpose_scope( MPKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the master key salt.
    trc( "masterKeySalt: keyScope=%s | #fullName=%s | fullName=%s",
            keyScope, mpw_hex_l( (uint32_t)mpw_utf8_char_count( fullName ), (char[9]){ 0 } ), fullName );
    size_t masterKeySaltSize = 0;
    uint8_t *masterKeySalt = NULL;
    if (!(mpw_push_string( &masterKeySalt, &masterKeySaltSize, keyScope ) &&
          mpw_push_int( &masterKeySalt, &masterKeySaltSize, (uint32_t)mpw_utf8_char_count( fullName ) ) &&
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
        trc( "  => masterKey.id: %s (algorithm: %d:0)", masterKey->keyID.hex, masterKey->algorithm );
    }
    return success;
}

bool mpw_service_key_v0(
        const MPServiceKey *serviceKey, const MPMasterKey *masterKey, const char *serviceName, MPCounterValue keyCounter,
        MPKeyPurpose keyPurpose, const char *keyContext) {

    const char *keyScope = mpw_purpose_scope( keyPurpose );
    trc( "keyScope: %s", keyScope );

    // OTP counter value.
    if (keyCounter == MPCounterValueTOTP)
        keyCounter = ((uint32_t)time( NULL ) / MP_otp_window) * MP_otp_window;

    // Calculate the service seed.
    trc( "serviceSalt: keyScope=%s | #serviceName=%s | serviceName=%s | keyCounter=%s | #keyContext=%s | keyContext=%s",
            keyScope, mpw_hex_l( (uint32_t)mpw_utf8_char_count( serviceName ), (char[9]){ 0 } ), serviceName,
            mpw_hex_l( keyCounter, (char[9]){ 0 } ),
            keyContext? mpw_hex_l( (uint32_t)mpw_utf8_char_count( keyContext ), (char[9]){ 0 } ): NULL, keyContext );
    size_t serviceSaltSize = 0;
    uint8_t *serviceSalt = NULL;
    if (!(mpw_push_string( &serviceSalt, &serviceSaltSize, keyScope ) &&
          mpw_push_int( &serviceSalt, &serviceSaltSize, (uint32_t)mpw_utf8_char_count( serviceName ) ) &&
          mpw_push_string( &serviceSalt, &serviceSaltSize, serviceName ) &&
          mpw_push_int( &serviceSalt, &serviceSaltSize, keyCounter ) &&
          (!keyContext? true:
           mpw_push_int( &serviceSalt, &serviceSaltSize, (uint32_t)mpw_utf8_char_count( keyContext ) ) &&
           mpw_push_string( &serviceSalt, &serviceSaltSize, keyContext ))) || !serviceSalt) {
        err( "Could not allocate service salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => serviceSalt.id: %s", mpw_id_buf( serviceSalt, serviceSaltSize ).hex );

    trc( "serviceKey: hmac-sha256( masterKey.id=%s, serviceSalt )", masterKey->keyID.hex );
    bool success = mpw_hash_hmac_sha256( (uint8_t *)serviceKey->bytes,
            masterKey->bytes, sizeof( masterKey->bytes ), serviceSalt, serviceSaltSize );
    mpw_free( &serviceSalt, serviceSaltSize );

    if (!success)
        err( "Could not derive service key: %s", strerror( errno ) );
    else {
        MPKeyID keyID = mpw_id_buf( serviceKey->bytes, sizeof( serviceKey->bytes ) );
        memcpy( (MPKeyID *)&serviceKey->keyID, &keyID, sizeof( serviceKey->keyID ) );
        trc( "  => serviceKey.id: %s (algorithm: %d:0)", serviceKey->keyID.hex, serviceKey->algorithm );
    }
    return success;
}

const char *mpw_service_template_password_v0(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *resultParam) {

    const char *_serviceKey = (const char *)serviceKey;

    // Determine the template.
    uint16_t seedByte;
    mpw_uint16( (uint16_t)_serviceKey[0], (uint8_t *)&seedByte );
    const char *template = mpw_type_template_v0( resultType, seedByte );
    trc( "template: %u => %s", seedByte, template );
    if (!template)
        return NULL;
    if (strlen( template ) > sizeof( *serviceKey )) {
        err( "Template too long for password seed: %zu", strlen( template ) );
        return NULL;
    }

    // Encode the password from the seed using the template.
    char *const servicePassword = calloc( strlen( template ) + 1, sizeof( char ) );
    for (size_t c = 0; c < strlen( template ); ++c) {
        mpw_uint16( (uint16_t)_serviceKey[c + 1], (uint8_t *)&seedByte );
        servicePassword[c] = mpw_class_character_v0( template[c], seedByte );
        trc( "  - class: %c, index: %5u (0x%.2hX) => character: %c",
                template[c], seedByte, seedByte, servicePassword[c] );
    }
    trc( "  => password: %s", servicePassword );

    return servicePassword;
}

const char *mpw_service_crypted_password_v0(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *cipherText) {

    if (!cipherText) {
        err( "Missing encrypted state." );
        return NULL;
    }
    if (strlen( cipherText ) % 4 != 0) {
        wrn( "Malformed encrypted state, not base64." );
        // This can happen if state was stored in a non-encrypted form, eg. login in old mpsites.
        return strdup( cipherText );
    }

    // Base64-decode
    char *hex = NULL;
    uint8_t *cipherBuf = calloc( 1, mpw_base64_decode_max( cipherText ) );
    size_t bufSize = mpw_base64_decode( cipherText, cipherBuf ), cipherBufSize = bufSize, hexSize = 0;
    if ((int)bufSize < 0) {
        err( "Base64 decoding error." );
        mpw_free( &cipherBuf, mpw_base64_decode_max( cipherText ) );
        return NULL;
    }
    trc( "b64 decoded: %zu bytes = %s", bufSize, hex = mpw_hex( cipherBuf, bufSize, hex, &hexSize ) );

    // Decrypt
    const uint8_t *plainBytes = mpw_aes_decrypt( masterKey->bytes, sizeof( masterKey->bytes ), cipherBuf, &bufSize );
    mpw_free( &cipherBuf, cipherBufSize );
    const char *plainText = mpw_strndup( (char *)plainBytes, bufSize );
    mpw_free( &plainBytes, bufSize );
    if (!plainText)
        err( "AES decryption error: %s", strerror( errno ) );
    else if (!mpw_utf8_char_count( plainText ))
        wrn( "decrypted -> plainText: %zu bytes = illegal UTF-8 = %s",
                bufSize, hex = mpw_hex( plainBytes, bufSize, hex, &hexSize ) );
    else
        trc( "decrypted -> plainText: %zu chars = %s :: %zu bytes = %s",
                strlen( plainText ), plainText, bufSize, hex = mpw_hex( plainBytes, bufSize, hex, &hexSize ) );
    mpw_free_string( &hex );

    return plainText;
}

const char *mpw_service_derived_password_v0(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *resultParam) {

    switch (resultType) {
        case MPResultTypeDeriveKey: {
            if (!resultParam) {
                err( "Missing key size parameter." );
                return NULL;
            }
            long parameter = strtol( resultParam, NULL, 10 );
            if (!parameter)
                parameter = 512;
            if (parameter < 128 || parameter > 512 || parameter % 8 != 0) {
                err( "Parameter is not a valid key size (should be 128 - 512): %s", resultParam );
                return NULL;
            }

            // Derive key
            uint8_t resultKey[parameter / 8];
            trc( "keySize: %u", sizeof( resultKey ) );
            if (!mpw_kdf_blake2b( resultKey, sizeof( resultKey ), serviceKey->bytes, sizeof( serviceKey->bytes ), NULL, 0, 0, NULL )) {
                err( "Could not derive result key: %s", strerror( errno ) );
                return NULL;
            }

            // Base64-encode
            size_t b64Max = mpw_base64_encode_max( sizeof( resultKey ) );
            char *b64Key = calloc( 1, b64Max + 1 );
            if (mpw_base64_encode( resultKey, sizeof( resultKey ), b64Key ) < 0) {
                err( "Base64 encoding error." );
                mpw_free_string( &b64Key );
            }
            else
                trc( "b64 encoded -> key: %s", b64Key );
            mpw_zero( &resultKey, sizeof( resultKey ) );

            return b64Key;
        }
        default:
            err( "Unsupported derived password type: %d", resultType );
            return NULL;
    }
}

const char *mpw_service_state_v0(
        const MPMasterKey *masterKey, const MPServiceKey *serviceKey, MPResultType resultType, const char *plainText) {

    // Encrypt
    char *hex = NULL;
    size_t bufSize = strlen( plainText ), hexSize = 0;
    const uint8_t *cipherBuf = mpw_aes_encrypt( masterKey->bytes, sizeof( masterKey->bytes ), (const uint8_t *)plainText, &bufSize );
    if (!cipherBuf) {
        err( "AES encryption error: %s", strerror( errno ) );
        return NULL;
    }
    trc( "cipherBuf: %zu bytes = %s", bufSize, hex = mpw_hex( cipherBuf, bufSize, hex, &hexSize ) );

    // Base64-encode
    size_t b64Max = mpw_base64_encode_max( bufSize );
    char *cipherText = calloc( 1, b64Max + 1 );
    if (mpw_base64_encode( cipherBuf, bufSize, cipherText ) < 0) {
        err( "Base64 encoding error." );
        mpw_free_string( &cipherText );
    }
    else
        trc( "b64 encoded -> cipherText: %s", cipherText );
    mpw_free( &cipherBuf, bufSize );
    mpw_free_string( &hex );

    return cipherText;
}
