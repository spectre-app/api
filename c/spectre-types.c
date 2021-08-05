// =============================================================================
// Created by Maarten Billemont on 2012-01-04.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

#include "spectre-types.h"
#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
#include <ctype.h>

#if SPECTRE_CPERCIVA
#include <scrypt/crypto_scrypt.h>
#include <scrypt/sha256.h>
#elif SPECTRE_SODIUM
#include "sodium.h"
#endif
SPECTRE_LIBS_END

const SpectreKeyID SpectreKeyIDUnset = { .hex = "" };

const SpectreIdenticon SpectreIdenticonUnset = {
        .leftArm = "",
        .body = "",
        .rightArm = "",
        .accessory = "",
        .color = SpectreIdenticonColorUnset,
};

bool spectre_id_valid(const SpectreKeyID *id) {

    return id && strlen( id->hex ) + 1 == sizeof( id->hex );
}

bool spectre_id_equals(const SpectreKeyID *id1, const SpectreKeyID *id2) {

    if (!id1 || !id2)
        return !id1 && !id2;

    return memcmp( id1->bytes, id2->bytes, sizeof( id1->bytes ) ) == OK;
}

const SpectreKeyID spectre_id_buf(const uint8_t *buf, const size_t size) {

    SpectreKeyID keyID = SpectreKeyIDUnset;

    if (!buf)
        return keyID;

#if SPECTRE_CPERCIVA
    SHA256_Buf( buf, size, keyID.bytes );
#elif SPECTRE_SODIUM
    crypto_hash_sha256( keyID.bytes, buf, size );
#else
#error No crypto support for spectre_id_buf.
#endif

    size_t hexSize = sizeof( keyID.hex );
    if (spectre_hex( keyID.bytes, sizeof( keyID.bytes ), keyID.hex, &hexSize ) != keyID.hex)
        err( "KeyID string pointer mismatch." );

    return keyID;
}

const SpectreKeyID spectre_id_str(const char hex[static 65]) {

    SpectreKeyID keyID = SpectreKeyIDUnset;

    size_t hexSize = 0;
    const uint8_t *hexBytes = spectre_unhex( hex, &hexSize );
    if (hexSize != sizeof( keyID.bytes ))
        wrn( "Not a valid key ID: %s", hex );

    else {
        memcpy( keyID.bytes, hexBytes, sizeof( keyID.bytes ) );
        spectre_hex( keyID.bytes, sizeof( keyID.bytes ), keyID.hex, &((size_t){ sizeof( keyID.hex ) }) );
    }

    spectre_free( &hexBytes, hexSize );
    return keyID;
}

const SpectreResultType spectre_type_named(const char *typeName) {

    // Find what password type is represented by the type letter.
    if (strlen( typeName ) == 1) {
        if ('0' == typeName[0])
            return SpectreResultNone;
        if ('x' == typeName[0])
            return SpectreResultTemplateMaximum;
        if ('l' == typeName[0])
            return SpectreResultTemplateLong;
        if ('m' == typeName[0])
            return SpectreResultTemplateMedium;
        if ('b' == typeName[0])
            return SpectreResultTemplateBasic;
        if ('s' == typeName[0])
            return SpectreResultTemplateShort;
        if ('i' == typeName[0])
            return SpectreResultTemplatePIN;
        if ('n' == typeName[0])
            return SpectreResultTemplateName;
        if ('p' == typeName[0])
            return SpectreResultTemplatePhrase;
        if ('P' == typeName[0])
            return SpectreResultStatePersonal;
        if ('D' == typeName[0])
            return SpectreResultStateDevice;
        if ('K' == typeName[0])
            return SpectreResultDeriveKey;
    }

    // Find what password type is represented by the type name.
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultNone ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultNone;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplateMaximum ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplateMaximum;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplateLong ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplateLong;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplateMedium ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplateMedium;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplateBasic ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplateBasic;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplateShort ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplateShort;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplatePIN ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplatePIN;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplateName ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplateName;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultTemplatePhrase ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultTemplatePhrase;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultStatePersonal ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultStatePersonal;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultStateDevice ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultStateDevice;
    if (spectre_strncasecmp( spectre_type_short_name( SpectreResultDeriveKey ), typeName, strlen( typeName ) ) == OK)
        return SpectreResultDeriveKey;

    wrn( "Not a generated type name: %s", typeName );
    return (SpectreResultType)ERR;
}

const char *spectre_type_abbreviation(const SpectreResultType resultType) {

    switch (resultType) {
        case SpectreResultNone:
            return "no";
        case SpectreResultTemplateMaximum:
            return "max";
        case SpectreResultTemplateLong:
            return "long";
        case SpectreResultTemplateMedium:
            return "med";
        case SpectreResultTemplateBasic:
            return "basic";
        case SpectreResultTemplateShort:
            return "short";
        case SpectreResultTemplatePIN:
            return "pin";
        case SpectreResultTemplateName:
            return "name";
        case SpectreResultTemplatePhrase:
            return "phrase";
        case SpectreResultStatePersonal:
            return "own";
        case SpectreResultStateDevice:
            return "device";
        case SpectreResultDeriveKey:
            return "key";
        default: {
            wrn( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char *spectre_type_short_name(const SpectreResultType resultType) {

    switch (resultType) {
        case SpectreResultNone:
            return "none";
        case SpectreResultTemplateMaximum:
            return "maximum";
        case SpectreResultTemplateLong:
            return "long";
        case SpectreResultTemplateMedium:
            return "medium";
        case SpectreResultTemplateBasic:
            return "basic";
        case SpectreResultTemplateShort:
            return "short";
        case SpectreResultTemplatePIN:
            return "pin";
        case SpectreResultTemplateName:
            return "name";
        case SpectreResultTemplatePhrase:
            return "phrase";
        case SpectreResultStatePersonal:
            return "personal";
        case SpectreResultStateDevice:
            return "device";
        case SpectreResultDeriveKey:
            return "key";
        default: {
            wrn( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char *spectre_type_long_name(const SpectreResultType resultType) {

    switch (resultType) {
        case SpectreResultNone:
            return "None";
        case SpectreResultTemplateMaximum:
            return "Maximum Security Password";
        case SpectreResultTemplateLong:
            return "Long Password";
        case SpectreResultTemplateMedium:
            return "Medium Password";
        case SpectreResultTemplateBasic:
            return "Basic Password";
        case SpectreResultTemplateShort:
            return "Short Password";
        case SpectreResultTemplatePIN:
            return "PIN";
        case SpectreResultTemplateName:
            return "Name";
        case SpectreResultTemplatePhrase:
            return "Phrase";
        case SpectreResultStatePersonal:
            return "Personal Password";
        case SpectreResultStateDevice:
            return "Device Private Password";
        case SpectreResultDeriveKey:
            return "Crypto Key";
        default: {
            wrn( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char **spectre_type_templates(const SpectreResultType type, size_t *count) {

    *count = 0;
    if (!(type & SpectreResultClassTemplate)) {
        wrn( "Not a generated type: %d", type );
        return NULL;
    }

    switch (type) {
        case SpectreResultTemplateMaximum:
            return spectre_strings( count,
                    "anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno", NULL );
        case SpectreResultTemplateLong:
            return spectre_strings( count,
                    "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno",
                    "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno",
                    "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno",
                    "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
                    "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno",
                    "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno",
                    "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno", NULL );
        case SpectreResultTemplateMedium:
            return spectre_strings( count,
                    "CvcnoCvc", "CvcCvcno", NULL );
        case SpectreResultTemplateShort:
            return spectre_strings( count,
                    "Cvcn", NULL );
        case SpectreResultTemplateBasic:
            return spectre_strings( count,
                    "aaanaaan", "aannaaan", "aaannaaa", NULL );
        case SpectreResultTemplatePIN:
            return spectre_strings( count,
                    "nnnn", NULL );
        case SpectreResultTemplateName:
            return spectre_strings( count,
                    "cvccvcvcv", NULL );
        case SpectreResultTemplatePhrase:
            return spectre_strings( count,
                    "cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv", NULL );
        default: {
            wrn( "Unknown generated type: %d", type );
            return NULL;
        }
    }
}

const char *spectre_type_template(const SpectreResultType type, const uint8_t templateIndex) {

    size_t count = 0;
    const char **templates = spectre_type_templates( type, &count );
    char const *template = templates && count? templates[templateIndex % count]: NULL;
    free( templates );

    return template;
}

const char *spectre_algorithm_short_name(const SpectreAlgorithm algorithm) {

    switch (algorithm) {
        case SpectreAlgorithmV0:
            return "v0";
        case SpectreAlgorithmV1:
            return "v1";
        case SpectreAlgorithmV2:
            return "v2";
        case SpectreAlgorithmV3:
            return "v3";
        default: {
            wrn( "Unknown algorithm: %d", algorithm );
            return NULL;
        }
    }
}

const char *spectre_algorithm_long_name(const SpectreAlgorithm algorithm) {

    switch (algorithm) {
        case SpectreAlgorithmV0:
            return "v0 (2012-03)";
        case SpectreAlgorithmV1:
            return "v1 (2012-07)";
        case SpectreAlgorithmV2:
            return "v2 (2014-09)";
        case SpectreAlgorithmV3:
            return "v3 (2015-01)";
        default: {
            wrn( "Unknown algorithm: %d", algorithm );
            return NULL;
        }
    }
}

const SpectreKeyPurpose spectre_purpose_named(const char *purposeName) {

    if (spectre_strncasecmp( spectre_purpose_name( SpectreKeyPurposeAuthentication ), purposeName, strlen( purposeName ) ) == OK)
        return SpectreKeyPurposeAuthentication;
    if (spectre_strncasecmp( spectre_purpose_name( SpectreKeyPurposeIdentification ), purposeName, strlen( purposeName ) ) == OK)
        return SpectreKeyPurposeIdentification;
    if (spectre_strncasecmp( spectre_purpose_name( SpectreKeyPurposeRecovery ), purposeName, strlen( purposeName ) ) == OK)
        return SpectreKeyPurposeRecovery;

    wrn( "Not a purpose name: %s", purposeName );
    return (SpectreKeyPurpose)ERR;
}

const char *spectre_purpose_name(const SpectreKeyPurpose purpose) {

    switch (purpose) {
        case SpectreKeyPurposeAuthentication:
            return "authentication";
        case SpectreKeyPurposeIdentification:
            return "identification";
        case SpectreKeyPurposeRecovery:
            return "recovery";
        default: {
            wrn( "Unknown purpose: %d", purpose );
            return NULL;
        }
    }
}

const char *spectre_purpose_scope(const SpectreKeyPurpose purpose) {

    switch (purpose) {
        case SpectreKeyPurposeAuthentication:
            return "com.lyndir.masterpassword";
        case SpectreKeyPurposeIdentification:
            return "com.lyndir.masterpassword.login";
        case SpectreKeyPurposeRecovery:
            return "com.lyndir.masterpassword.answer";
        default: {
            wrn( "Unknown purpose: %d", purpose );
            return NULL;
        }
    }
}

const char *spectre_class_characters(const char characterClass) {

    switch (characterClass) {
        case 'V':
            return "AEIOU";
        case 'C':
            return "BCDFGHJKLMNPQRSTVWXYZ";
        case 'v':
            return "aeiou";
        case 'c':
            return "bcdfghjklmnpqrstvwxyz";
        case 'A':
            return "AEIOUBCDFGHJKLMNPQRSTVWXYZ";
        case 'a':
            return "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
        case 'n':
            return "0123456789";
        case 'o':
            return "@&%?,=[]_:-+*$#!'^~;()/.";
        case 'x':
            return "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";
        case ' ':
            return " ";
        default: {
            wrn( "Unknown character class: %c", characterClass );
            return NULL;
        }
    }
}

const char spectre_class_character(const char characterClass, const uint8_t seedByte) {

    const char *classCharacters = spectre_class_characters( characterClass );
    if (!classCharacters || !strlen( classCharacters ))
        return '\0';

    return classCharacters[seedByte % strlen( classCharacters )];
}
