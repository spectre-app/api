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

#include "spectre-algorithm_v0.h"
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

// Algorithm version helpers.
const char *spectre_type_template_v0(const SpectreResultType type, uint16_t templateIndex) {

    size_t count = 0;
    const char **templates = spectre_type_templates( type, &count );
    char const *template = templates && count? templates[templateIndex % count]: NULL;
    free( templates );

    return template;
}

const char spectre_class_character_v0(char characterClass, uint16_t classIndex) {

    const char *classCharacters = spectre_class_characters( characterClass );
    if (!classCharacters)
        return '\0';

    return classCharacters[classIndex % strlen( classCharacters )];
}

// Algorithm version overrides.
bool spectre_user_key_v0(
        const SpectreUserKey *userKey, const char *userName, const char *userSecret) {

    const char *keyScope = spectre_purpose_scope( SpectreKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the user key salt.
    trc( "userKeySalt: keyScope=%s | #userName=%s | userName=%s",
            keyScope, spectre_hex_l( (uint32_t)spectre_utf8_char_count( userName ), (char[9]){ 0 } ), userName );
    size_t userKeySaltSize = 0;
    uint8_t *userKeySalt = NULL;
    if (!(spectre_buf_push( &userKeySalt, &userKeySaltSize, keyScope ) &&
          spectre_buf_push( &userKeySalt, &userKeySaltSize, (uint32_t)spectre_utf8_char_count( userName ) ) &&
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
        trc( "  => userKey.id: %s (algorithm: %d:0)", userKey->keyID.hex, userKey->algorithm );
    }
    return success;
}

bool spectre_site_key_v0(
        const SpectreSiteKey *siteKey, const SpectreUserKey *userKey, const char *siteName,
        SpectreCounter keyCounter, SpectreKeyPurpose keyPurpose, const char *keyContext) {

    const char *keyScope = spectre_purpose_scope( keyPurpose );
    trc( "keyScope: %s", keyScope );

    // OTP counter value.
    if (keyCounter == SpectreCounterTOTP)
        keyCounter = ((SpectreCounter)time( NULL ) / Spectre_otp_window) * Spectre_otp_window;

    // Calculate the site seed.
    trc( "siteSalt: keyScope=%s | #siteName=%s | siteName=%s | keyCounter=%s | #keyContext=%s | keyContext=%s",
            keyScope, spectre_hex_l( (uint32_t)spectre_utf8_char_count( siteName ), (char[9]){ 0 } ), siteName,
            spectre_hex_l( keyCounter, (char[9]){ 0 } ),
            keyContext? spectre_hex_l( (uint32_t)spectre_utf8_char_count( keyContext ), (char[9]){ 0 } ): NULL, keyContext );
    size_t siteSaltSize = 0;
    uint8_t *siteSalt = NULL;
    if (!(spectre_buf_push( &siteSalt, &siteSaltSize, keyScope ) &&
          spectre_buf_push( &siteSalt, &siteSaltSize, (uint32_t)spectre_utf8_char_count( siteName ) ) &&
          spectre_buf_push( &siteSalt, &siteSaltSize, siteName ) &&
          spectre_buf_push( &siteSalt, &siteSaltSize, (uint32_t)keyCounter ) &&
          (!keyContext? true:
           spectre_buf_push( &siteSalt, &siteSaltSize, (uint32_t)spectre_utf8_char_count( keyContext ) ) &&
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
        trc( "  => siteKey.id: %s (algorithm: %d:0)", siteKey->keyID.hex, siteKey->algorithm );
    }
    return success;
}

const char *spectre_site_template_password_v0(
        __unused const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, __unused const char *resultParam) {

    const char *_siteKey = (const char *)siteKey->bytes;

    // Determine the template.
    uint16_t seedByte;
    spectre_uint16( (uint16_t)_siteKey[0], (uint8_t *)&seedByte );
    const char *template = spectre_type_template_v0( resultType, seedByte );
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
        spectre_uint16( (uint16_t)_siteKey[c + 1], (uint8_t *)&seedByte );
        sitePassword[c] = spectre_class_character_v0( template[c], seedByte );
        trc( "  - class: %c, index: %5u (0x%.2hX) => character: %c",
                template[c], seedByte, seedByte, sitePassword[c] );
    }
    trc( "  => password: %s", sitePassword );

    return sitePassword;
}

const char *spectre_site_crypted_password_v0(
        const SpectreUserKey *userKey, __unused const SpectreSiteKey *siteKey, __unused SpectreResultType resultType, const char *cipherText) {

    if (!cipherText) {
        err( "Missing encrypted state." );
        return NULL;
    }
    size_t cipherLength = strlen( cipherText );
    if (cipherLength % 4 != 0) {
        wrn( "Malformed encrypted state, not base64." );
        // This can happen if state was stored in a non-encrypted form, eg. login in old mpsites.
        return spectre_strdup( cipherText );
    }

    // Base64-decode
    char *hex = NULL;
    uint8_t *cipherBuf = calloc( 1, spectre_base64_decode_max( cipherLength ) );
    size_t bufSize = spectre_base64_decode( cipherText, cipherBuf ), cipherBufSize = bufSize, hexSize = 0;
    if ((int)bufSize < 0) {
        err( "Base64 decoding error." );
        spectre_free( &cipherBuf, spectre_base64_decode_max( cipherLength ) );
        return NULL;
    }
    trc( "b64 decoded: %zu bytes = %s", bufSize, hex = spectre_hex( cipherBuf, bufSize, hex, &hexSize ) );

    // Decrypt
    const uint8_t *plainBytes = spectre_aes_decrypt( userKey->bytes, sizeof( userKey->bytes ), cipherBuf, &bufSize );
    spectre_free( &cipherBuf, cipherBufSize );
    const char *plainText = spectre_strndup( (char *)plainBytes, bufSize );
    if (!plainText)
        err( "AES decryption error: %s", strerror( errno ) );
    else if (!spectre_utf8_char_count( plainText ))
        trc( "decrypted -> plainText: %zu chars = (illegal UTF-8) :: %zu bytes = %s",
                strlen( plainText ), bufSize, hex = spectre_hex( plainBytes, bufSize, hex, &hexSize ) );
    else
        trc( "decrypted -> plainText: %zu chars = %s :: %zu bytes = %s",
                strlen( plainText ), plainText, bufSize, hex = spectre_hex( plainBytes, bufSize, hex, &hexSize ) );
    spectre_free( &plainBytes, bufSize );
    spectre_free_string( &hex );

    return plainText;
}

const char *spectre_site_derived_password_v0(
        __unused const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam) {

    switch (resultType) {
        case SpectreResultDeriveKey: {
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
            if (!spectre_kdf_blake2b( resultKey, sizeof( resultKey ), siteKey->bytes, sizeof( siteKey->bytes ), NULL, 0, 0, NULL )) {
                err( "Could not derive result key: %s", strerror( errno ) );
                return NULL;
            }

            // Base64-encode
            char *b64Key = calloc( 1, spectre_base64_encode_max( sizeof( resultKey ) ) );
            if (spectre_base64_encode( resultKey, sizeof( resultKey ), b64Key ) < 0) {
                err( "Base64 encoding error." );
                spectre_free_string( &b64Key );
            }
            else
                trc( "b64 encoded -> key: %s", b64Key );
            spectre_zero( &resultKey, sizeof( resultKey ) );

            return b64Key;
        }
        default:
            err( "Unsupported derived password type: %d", resultType );
            return NULL;
    }
}

const char *spectre_site_state_v0(
        const SpectreUserKey *userKey, __unused const SpectreSiteKey *siteKey, __unused SpectreResultType resultType, const char *plainText) {

    // Encrypt
    char *hex = NULL;
    size_t bufSize = strlen( plainText ), hexSize = 0;
    const uint8_t *cipherBuf = spectre_aes_encrypt( userKey->bytes, sizeof( userKey->bytes ), (const uint8_t *)plainText, &bufSize );
    if (!cipherBuf) {
        err( "AES encryption error: %s", strerror( errno ) );
        return NULL;
    }
    trc( "cipherBuf: %zu bytes = %s", bufSize, hex = spectre_hex( cipherBuf, bufSize, hex, &hexSize ) );

    // Base64-encode
    char *cipherText = calloc( 1, spectre_base64_encode_max( bufSize ) );
    if (spectre_base64_encode( cipherBuf, bufSize, cipherText ) < 0) {
        err( "Base64 encoding error." );
        spectre_free_string( &cipherText );
    }
    else
        trc( "b64 encoded -> cipherText: %s", cipherText );
    spectre_free( &cipherBuf, bufSize );
    spectre_free_string( &hex );

    return cipherText;
}
