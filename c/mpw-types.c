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

#include "mpw-types.h"
#include "mpw-util.h"

MP_LIBS_BEGIN
#include <string.h>
#include <ctype.h>

#if MPW_CPERCIVA
#include <scrypt/crypto_scrypt.h>
#include <scrypt/sha256.h>
#elif MPW_SODIUM
#include "sodium.h"
#endif
MP_LIBS_END

const MPKeyID MPNoKeyID = { .hex = "" };

const MPIdenticon MPIdenticonUnset = {
        .leftArm = "",
        .body = "",
        .rightArm = "",
        .accessory = "",
        .color = MPIdenticonColorUnset,
};

bool mpw_id_valid(const MPKeyID *id) {

    return id && strlen( id->hex ) + 1 == sizeof( id->hex );
}

bool mpw_id_equals(const MPKeyID *id1, const MPKeyID *id2) {

    if (!id1 || !id2)
        return !id1 && !id2;

    return memcmp( id1->bytes, id2->bytes, sizeof( id1->bytes ) ) == OK;
}

const MPKeyID mpw_id_buf(const uint8_t *buf, const size_t size) {

    MPKeyID keyID = MPNoKeyID;

    if (!buf)
        return keyID;

#if MPW_CPERCIVA
    SHA256_Buf( buf, size, keyID.bytes );
#elif MPW_SODIUM
    crypto_hash_sha256( keyID.bytes, buf, size );
#else
#error No crypto support for mpw_id_buf.
#endif

    size_t hexSize = sizeof( keyID.hex );
    if (mpw_hex( keyID.bytes, sizeof( keyID.bytes ), keyID.hex, &hexSize ) != keyID.hex)
        err( "KeyID string pointer mismatch." );

    return keyID;
}

const MPKeyID mpw_id_str(const char hex[static 65]) {

    MPKeyID keyID = MPNoKeyID;

    size_t hexSize = 0;
    const uint8_t *hexBytes = mpw_unhex( hex, &hexSize );
    if (hexSize != sizeof( keyID.bytes ))
        wrn( "Not a valid key ID: %s", hex );

    else {
        memcpy( keyID.bytes, hexBytes, sizeof( keyID.bytes ) );
        mpw_hex( keyID.bytes, sizeof( keyID.bytes ), keyID.hex, &((size_t){ sizeof( keyID.hex ) }) );
    }

    mpw_free( &hexBytes, hexSize );
    return keyID;
}

const MPResultType mpw_type_named(const char *typeName) {

    // Find what password type is represented by the type letter.
    if (strlen( typeName ) == 1) {
        if ('0' == typeName[0])
            return MPResultTypeNone;
        if ('x' == typeName[0])
            return MPResultTypeTemplateMaximum;
        if ('l' == typeName[0])
            return MPResultTypeTemplateLong;
        if ('m' == typeName[0])
            return MPResultTypeTemplateMedium;
        if ('b' == typeName[0])
            return MPResultTypeTemplateBasic;
        if ('s' == typeName[0])
            return MPResultTypeTemplateShort;
        if ('i' == typeName[0])
            return MPResultTypeTemplatePIN;
        if ('n' == typeName[0])
            return MPResultTypeTemplateName;
        if ('p' == typeName[0])
            return MPResultTypeTemplatePhrase;
        if ('P' == typeName[0])
            return MPResultTypeStatefulPersonal;
        if ('D' == typeName[0])
            return MPResultTypeStatefulDevice;
        if ('K' == typeName[0])
            return MPResultTypeDeriveKey;
    }

    // Find what password type is represented by the type name.
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeNone ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeNone;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplateMaximum ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplateMaximum;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplateLong ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplateLong;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplateMedium ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplateMedium;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplateBasic ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplateBasic;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplateShort ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplateShort;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplatePIN ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplatePIN;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplateName ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplateName;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeTemplatePhrase ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeTemplatePhrase;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeStatefulPersonal ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeStatefulPersonal;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeStatefulDevice ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeStatefulDevice;
    if (mpw_strncasecmp( mpw_type_short_name( MPResultTypeDeriveKey ), typeName, strlen( typeName ) ) == OK)
        return MPResultTypeDeriveKey;

    dbg( "Not a generated type name: %s", typeName );
    return (MPResultType)ERR;
}

const char *mpw_type_abbreviation(const MPResultType resultType) {

    switch (resultType) {
        case MPResultTypeNone:
            return "no";
        case MPResultTypeTemplateMaximum:
            return "max";
        case MPResultTypeTemplateLong:
            return "long";
        case MPResultTypeTemplateMedium:
            return "med";
        case MPResultTypeTemplateBasic:
            return "basic";
        case MPResultTypeTemplateShort:
            return "short";
        case MPResultTypeTemplatePIN:
            return "pin";
        case MPResultTypeTemplateName:
            return "name";
        case MPResultTypeTemplatePhrase:
            return "phrase";
        case MPResultTypeStatefulPersonal:
            return "own";
        case MPResultTypeStatefulDevice:
            return "device";
        case MPResultTypeDeriveKey:
            return "key";
        default: {
            dbg( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char *mpw_type_short_name(const MPResultType resultType) {

    switch (resultType) {
        case MPResultTypeNone:
            return "none";
        case MPResultTypeTemplateMaximum:
            return "maximum";
        case MPResultTypeTemplateLong:
            return "long";
        case MPResultTypeTemplateMedium:
            return "medium";
        case MPResultTypeTemplateBasic:
            return "basic";
        case MPResultTypeTemplateShort:
            return "short";
        case MPResultTypeTemplatePIN:
            return "pin";
        case MPResultTypeTemplateName:
            return "name";
        case MPResultTypeTemplatePhrase:
            return "phrase";
        case MPResultTypeStatefulPersonal:
            return "personal";
        case MPResultTypeStatefulDevice:
            return "device";
        case MPResultTypeDeriveKey:
            return "key";
        default: {
            dbg( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char *mpw_type_long_name(const MPResultType resultType) {

    switch (resultType) {
        case MPResultTypeNone:
            return "None";
        case MPResultTypeTemplateMaximum:
            return "Maximum Security Password";
        case MPResultTypeTemplateLong:
            return "Long Password";
        case MPResultTypeTemplateMedium:
            return "Medium Password";
        case MPResultTypeTemplateBasic:
            return "Basic Password";
        case MPResultTypeTemplateShort:
            return "Short Password";
        case MPResultTypeTemplatePIN:
            return "PIN";
        case MPResultTypeTemplateName:
            return "Name";
        case MPResultTypeTemplatePhrase:
            return "Phrase";
        case MPResultTypeStatefulPersonal:
            return "Personal Password";
        case MPResultTypeStatefulDevice:
            return "Device Private Password";
        case MPResultTypeDeriveKey:
            return "Crypto Key";
        default: {
            dbg( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char **mpw_type_templates(const MPResultType type, size_t *count) {

    if (!(type & MPResultTypeClassTemplate)) {
        dbg( "Not a generated type: %d", type );
        return NULL;
    }

    switch (type) {
        case MPResultTypeTemplateMaximum:
            return mpw_strings( count,
                    "anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno", NULL );
        case MPResultTypeTemplateLong:
            return mpw_strings( count,
                    "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno",
                    "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno",
                    "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno",
                    "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
                    "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno",
                    "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno",
                    "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno", NULL );
        case MPResultTypeTemplateMedium:
            return mpw_strings( count,
                    "CvcnoCvc", "CvcCvcno", NULL );
        case MPResultTypeTemplateShort:
            return mpw_strings( count,
                    "Cvcn", NULL );
        case MPResultTypeTemplateBasic:
            return mpw_strings( count,
                    "aaanaaan", "aannaaan", "aaannaaa", NULL );
        case MPResultTypeTemplatePIN:
            return mpw_strings( count,
                    "nnnn", NULL );
        case MPResultTypeTemplateName:
            return mpw_strings( count,
                    "cvccvcvcv", NULL );
        case MPResultTypeTemplatePhrase:
            return mpw_strings( count,
                    "cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv", NULL );
        default: {
            dbg( "Unknown generated type: %d", type );
            return NULL;
        }
    }
}

const char *mpw_type_template(const MPResultType type, const uint8_t templateIndex) {

    size_t count = 0;
    const char **templates = mpw_type_templates( type, &count );
    char const *template = templates && count? templates[templateIndex % count]: NULL;
    free( templates );

    return template;
}

const MPKeyPurpose mpw_purpose_named(const char *purposeName) {

    if (mpw_strncasecmp( mpw_purpose_name( MPKeyPurposeAuthentication ), purposeName, strlen( purposeName ) ) == OK)
        return MPKeyPurposeAuthentication;
    if (mpw_strncasecmp( mpw_purpose_name( MPKeyPurposeIdentification ), purposeName, strlen( purposeName ) ) == OK)
        return MPKeyPurposeIdentification;
    if (mpw_strncasecmp( mpw_purpose_name( MPKeyPurposeRecovery ), purposeName, strlen( purposeName ) ) == OK)
        return MPKeyPurposeRecovery;

    dbg( "Not a purpose name: %s", purposeName );
    return (MPKeyPurpose)ERR;
}

const char *mpw_purpose_name(const MPKeyPurpose purpose) {

    switch (purpose) {
        case MPKeyPurposeAuthentication:
            return "authentication";
        case MPKeyPurposeIdentification:
            return "identification";
        case MPKeyPurposeRecovery:
            return "recovery";
        default: {
            dbg( "Unknown purpose: %d", purpose );
            return NULL;
        }
    }
}

const char *mpw_purpose_scope(const MPKeyPurpose purpose) {

    switch (purpose) {
        case MPKeyPurposeAuthentication:
            return "com.lyndir.masterpassword";
        case MPKeyPurposeIdentification:
            return "com.lyndir.masterpassword.login";
        case MPKeyPurposeRecovery:
            return "com.lyndir.masterpassword.answer";
        default: {
            dbg( "Unknown purpose: %d", purpose );
            return NULL;
        }
    }
}

const char *mpw_class_characters(const char characterClass) {

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
            dbg( "Unknown character class: %c", characterClass );
            return NULL;
        }
    }
}

const char mpw_class_character(const char characterClass, const uint8_t seedByte) {

    const char *classCharacters = mpw_class_characters( characterClass );
    if (!classCharacters || !strlen( classCharacters ))
        return '\0';

    return classCharacters[seedByte % strlen( classCharacters )];
}
