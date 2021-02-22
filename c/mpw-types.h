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

#ifndef _MPW_TYPES_H
#define _MPW_TYPES_H

#ifndef MP_LIBS_BEGIN
#define MP_LIBS_BEGIN
#define MP_LIBS_END
#endif

MP_LIBS_BEGIN
#define __STDC_WANT_LIB_EXT1__ 1
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
MP_LIBS_END

#ifndef __unused
#define __unused
#endif

#ifdef NS_ENUM
#define mpw_enum(_type, _name) NS_ENUM(_type, _name)
#elif __clang__ || __has_feature( c_fixed_enum ) || __has_feature( objc_fixed_enum ) || __has_feature( cxx_fixed_enum )
#define mpw_enum(_type, _name) enum _name : _type _name; enum _name : _type
#else
#define mpw_enum(_type, _name) _type _name; enum _name
#endif

#ifdef NS_OPTIONS
#define mpw_opts(_type, _name) NS_OPTIONS(_type, _name)
#elif __clang__ || __has_feature( c_fixed_enum ) || __has_feature( objc_fixed_enum ) || __has_feature( cxx_fixed_enum )
#define mpw_opts(_type, _name) enum _name : _type _name; enum _name : _type
#else
#define mpw_opts(_type, _name) _type _name; enum _name
#endif

//// Types.

typedef mpw_enum( unsigned int, MPAlgorithmVersion ) {
    /** V0 incorrectly performed host-endian math with bytes translated into 16-bit network-endian. */
    MPAlgorithmVersionV0,
    /** V1 incorrectly sized site name fields by character count rather than byte count. */
    MPAlgorithmVersionV1,
    /** V2 incorrectly sized user name fields by character count rather than byte count. */
    MPAlgorithmVersionV2,
    /** V3 is the current version. */
    MPAlgorithmVersionV3,

    MPAlgorithmVersionCurrent = MPAlgorithmVersionV3,
    MPAlgorithmVersionFirst = MPAlgorithmVersionV0,
    MPAlgorithmVersionLast = MPAlgorithmVersionV3,
};

typedef struct {
    /** SHA-256-sized hash */
    uint8_t bytes[256 / 8]; // SHA-256
    /** Hex c-string of the hash */
    char hex[2 * (256 / 8) + 1];
} MPKeyID;
extern const MPKeyID MPNoKeyID;

typedef struct {
    /** The cryptographic key */
    const uint8_t bytes[64];
    /** The key's identity */
    const MPKeyID keyID;
    /** The algorithm the key was made by & for */
    const MPAlgorithmVersion algorithm;
} MPUserKey;

typedef struct {
    /** The cryptographic key */
    const uint8_t bytes[256 / 8]; // HMAC-SHA-256
    /** The key's identity */
    const MPKeyID keyID;
    /** The algorithm the key was made by & for */
    const MPAlgorithmVersion algorithm;
} MPSiteKey;

typedef mpw_enum( uint8_t, MPKeyPurpose ) {
    /** Generate a key for authentication. */
    MPKeyPurposeAuthentication,
    /** Generate a name for identification. */
    MPKeyPurposeIdentification,
    /** Generate a recovery token. */
    MPKeyPurposeRecovery,
};

// bit 4 - 9
typedef mpw_opts( uint16_t, MPResultTypeClass ) {
    /** Use the site key to generate a result from a template. */
    MPResultTypeClassTemplate = 1 << 4,
    /** Use the site key to encrypt and decrypt a stateful entity. */
    MPResultTypeClassStateful = 1 << 5,
    /** Use the site key to derive a site-specific object. */
    MPResultTypeClassDerive = 1 << 6,
};

// bit 10 - 15
typedef mpw_opts( uint16_t, MPSiteFeature ) {
    /** Export the key-protected content data. */
    MPSiteFeatureExportContent = 1 << 10,
    /** Never export content. */
    MPSiteFeatureDevicePrivate = 1 << 11,
    /** Don't use this as the primary authentication result type. */
    MPSiteFeatureAlternative = 1 << 12,
};

// bit 0-3 | MPResultTypeClass | MPSiteFeature
typedef mpw_enum( uint32_t, MPResultType ) {
    /** 0: Don't produce a result */
    MPResultTypeNone = 0,

    /** 16: pg^VMAUBk5x3p%HP%i4= */
    MPResultTypeTemplateMaximum = 0x0 | MPResultTypeClassTemplate | 0x0,
    /** 17: BiroYena8:Kixa */
    MPResultTypeTemplateLong = 0x1 | MPResultTypeClassTemplate | 0x0,
    /** 18: BirSuj0- */
    MPResultTypeTemplateMedium = 0x2 | MPResultTypeClassTemplate | 0x0,
    /** 19: Bir8 */
    MPResultTypeTemplateShort = 0x3 | MPResultTypeClassTemplate | 0x0,
    /** 20: pO98MoD0 */
    MPResultTypeTemplateBasic = 0x4 | MPResultTypeClassTemplate | 0x0,
    /** 21: 2798 */
    MPResultTypeTemplatePIN = 0x5 | MPResultTypeClassTemplate | 0x0,
    /** 30: birsujano */
    MPResultTypeTemplateName = 0xE | MPResultTypeClassTemplate | 0x0,
    /** 31: bir yennoquce fefi */
    MPResultTypeTemplatePhrase = 0xF | MPResultTypeClassTemplate | 0x0,

    /** 1056: Custom saved result. */
    MPResultTypeStatefulPersonal = 0x0 | MPResultTypeClassStateful | MPSiteFeatureExportContent,
    /** 2081: Custom saved result that should not be exported from the device. */
    MPResultTypeStatefulDevice = 0x1 | MPResultTypeClassStateful | MPSiteFeatureDevicePrivate,

    /** 4160: Derive a unique binary key. */
    MPResultTypeDeriveKey = 0x0 | MPResultTypeClassDerive | MPSiteFeatureAlternative,

    MPResultTypeDefaultResult = MPResultTypeTemplateLong,
    MPResultTypeDefaultLogin = MPResultTypeTemplateName,
};

typedef mpw_enum ( uint32_t, MPCounterValue ) {
    /** Use a time-based counter value, resulting in a TOTP generator. */
    MPCounterValueTOTP = 0,
    /** The initial value for a site's counter. */
    MPCounterValueInitial = 1,

    MPCounterValueDefault = MPCounterValueInitial,
    MPCounterValueFirst = MPCounterValueTOTP,
    MPCounterValueLast = UINT32_MAX,
};

/** These colours are compatible with the original ANSI SGR. */
typedef mpw_enum( uint8_t, MPIdenticonColor ) {
    MPIdenticonColorUnset,
    MPIdenticonColorRed,
    MPIdenticonColorGreen,
    MPIdenticonColorYellow,
    MPIdenticonColorBlue,
    MPIdenticonColorMagenta,
    MPIdenticonColorCyan,
    MPIdenticonColorMono,

    MPIdenticonColorFirst = MPIdenticonColorRed,
    MPIdenticonColorLast = MPIdenticonColorMono,
};

typedef struct {
    const char *leftArm;
    const char *body;
    const char *rightArm;
    const char *accessory;
    MPIdenticonColor color;
} MPIdenticon;
extern const MPIdenticon MPIdenticonUnset;

//// Type utilities.

/** Check whether the fingerprint is valid.
 * @return true if the fingerprints represents a fully complete print for a buffer. */
bool mpw_id_valid(const MPKeyID *id1);
/** Compare two fingerprints for equality.
 * @return true if the buffers represent identical fingerprints or are both NULL. */
bool mpw_id_equals(const MPKeyID *id1, const MPKeyID *id2);
/** Encode a fingerprint for a buffer. */
const MPKeyID mpw_id_buf(const uint8_t *buf, const size_t size);
/** Reconstruct a fingerprint from its hexadecimal string representation. */
const MPKeyID mpw_id_str(const char hex[static 65]);

/**
 * @return The purpose represented by the given name or ERR if the name does not represent a known purpose.
 */
const MPKeyPurpose mpw_purpose_named(const char *purposeName);
/**
 * @return The standard name (static) for the given purpose or NULL if the purpose is not known.
 */
const char *mpw_purpose_name(const MPKeyPurpose purpose);
/**
 * @return The scope identifier (static) to apply when encoding for the given purpose or NULL if the purpose is not known.
 */
const char *mpw_purpose_scope(const MPKeyPurpose purpose);

/**
 * @return The result type represented by the given name or ERR if the name does not represent a known type.
 */
const MPResultType mpw_type_named(const char *typeName);
/**
 * @return The standard identifying name (static) for the given result type or NULL if the type is not known.
 */
const char *mpw_type_abbreviation(const MPResultType resultType);
/**
 * @return The standard identifying name (static) for the given result type or NULL if the type is not known.
 */
const char *mpw_type_short_name(const MPResultType resultType);
/**
 * @return The descriptive name (static) for the given result type or NULL if the type is not known.
 */
const char *mpw_type_long_name(const MPResultType resultType);

/**
 * @return An array (allocated, count) of strings (static) that express the templates to use for the given type.
 *         NULL if the type is not known or is not a MPResultTypeClassTemplate.
 */
const char **mpw_type_templates(const MPResultType type, size_t *count);
/**
 * @return A C-string (static) that contains the result encoding template of the given type for a seed that starts with the given byte.
 *         NULL if the type is not known or is not a MPResultTypeClassTemplate.
 */
const char *mpw_type_template(const MPResultType type, const uint8_t templateIndex);

/**
 * @return A C-string (static) with all the characters in the given character class or NULL if the character class is not known.
 */
const char *mpw_class_characters(const char characterClass);
/**
 * @return A character from given character class that encodes the given byte or NUL if the character class is not known or is empty.
 */
const char mpw_class_character(const char characterClass, const uint8_t seedByte);

#endif // _MPW_TYPES_H
