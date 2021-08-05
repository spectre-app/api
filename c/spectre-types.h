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

#ifndef _SPECTRE_TYPES_H
#define _SPECTRE_TYPES_H

#ifndef SPECTRE_LIBS_BEGIN
#define SPECTRE_LIBS_BEGIN
#define SPECTRE_LIBS_END
#endif

SPECTRE_LIBS_BEGIN
#define __STDC_WANT_LIB_EXT1__ 1
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
SPECTRE_LIBS_END

#ifndef __unused
#define __unused
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifdef NS_ENUM
#define spectre_enum(_type, _name) NS_ENUM(_type, _name)
#elif __clang__ || __has_feature( c_fixed_enum ) || __has_feature( objc_fixed_enum ) || __has_feature( cxx_fixed_enum )
#define spectre_enum(_type, _name) _type _name; enum _name : _type
#else
#define spectre_enum(_type, _name) _type _name; enum _name
#endif

#ifdef NS_OPTIONS
#define spectre_opts(_type, _name) NS_OPTIONS(_type, _name)
#elif __clang__ || __has_feature( c_fixed_enum ) || __has_feature( objc_fixed_enum ) || __has_feature( cxx_fixed_enum )
#define spectre_opts(_type, _name) _type _name; enum _name : _type
#else
#define spectre_opts(_type, _name) _type _name; enum _name
#endif

//// Types.

typedef spectre_enum( unsigned int, SpectreAlgorithm ) {
    /** (2012-03-05) V0 incorrectly performed host-endian math with bytes translated into 16-bit network-endian. */
    SpectreAlgorithmV0,
    /** (2012-07-17) V1 incorrectly sized site name fields by character count rather than byte count. */
    SpectreAlgorithmV1,
    /** (2014-09-24) V2 incorrectly sized user name fields by character count rather than byte count. */
    SpectreAlgorithmV2,
    /** (2015-01-15) V3 is the current version. */
    SpectreAlgorithmV3,

    SpectreAlgorithmCurrent = SpectreAlgorithmV3,
    SpectreAlgorithmFirst = SpectreAlgorithmV0,
    SpectreAlgorithmLast = SpectreAlgorithmV3,
};

typedef struct {
    /** SHA-256-sized hash */
    uint8_t bytes[256 / 8]; // SHA-256
    /** Hex c-string of the hash */
    char hex[2 * (256 / 8) + 1];
} SpectreKeyID;
extern const SpectreKeyID SpectreKeyIDUnset;

typedef struct {
    /** The cryptographic key */
    const uint8_t bytes[512 / 8];
    /** The key's identity */
    const SpectreKeyID keyID;
    /** The algorithm the key was made by & for */
    const SpectreAlgorithm algorithm;
} SpectreUserKey;

typedef struct {
    /** The cryptographic key */
    const uint8_t bytes[256 / 8]; // HMAC-SHA-256
    /** The key's identity */
    const SpectreKeyID keyID;
    /** The algorithm the key was made by & for */
    const SpectreAlgorithm algorithm;
} SpectreSiteKey;

typedef spectre_enum( uint8_t, SpectreKeyPurpose ) {
    /** Generate a key for authentication. */
    SpectreKeyPurposeAuthentication,
    /** Generate a name for identification. */
    SpectreKeyPurposeIdentification,
    /** Generate a recovery token. */
    SpectreKeyPurposeRecovery,
};

// bit 4 - 9
typedef spectre_opts( uint16_t, SpectreResultClass ) {
    /** Use the site key to generate a result from a template. */
    SpectreResultClassTemplate = 1 << 4,
    /** Use the site key to encrypt and decrypt a stateful entity. */
    SpectreResultClassStateful = 1 << 5,
    /** Use the site key to derive a site-specific object. */
    SpectreResultClassDerive = 1 << 6,
};

// bit 10 - 15
typedef spectre_opts( uint16_t, SpectreResultFeature ) {
    SpectreResultFeatureNone = 0,
    /** Export the key-protected content data. */
    SpectreResultFeatureExportContent = 1 << 10,
    /** Never export content. */
    SpectreResultFeatureDevicePrivate = 1 << 11,
    /** Don't use this as the primary authentication result type. */
    SpectreResultFeatureAlternate = 1 << 12,
};

// bit 0-3 | SpectreResultClass | SpectreResultFeature
typedef spectre_enum( uint32_t, SpectreResultType ) {
    /** 0: Don't produce a result */
    SpectreResultNone = 0,

    /** 16: pg^VMAUBk5x3p%HP%i4= */
    SpectreResultTemplateMaximum = 0x0 | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 17: BiroYena8:Kixa */
    SpectreResultTemplateLong = 0x1 | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 18: BirSuj0- */
    SpectreResultTemplateMedium = 0x2 | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 19: Bir8 */
    SpectreResultTemplateShort = 0x3 | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 20: pO98MoD0 */
    SpectreResultTemplateBasic = 0x4 | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 21: 2798 */
    SpectreResultTemplatePIN = 0x5 | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 30: birsujano */
    SpectreResultTemplateName = 0xE | SpectreResultClassTemplate | SpectreResultFeatureNone,
    /** 31: bir yennoquce fefi */
    SpectreResultTemplatePhrase = 0xF | SpectreResultClassTemplate | SpectreResultFeatureNone,

    /** 1056: Custom saved result. */
    SpectreResultStatePersonal = 0x0 | SpectreResultClassStateful | SpectreResultFeatureExportContent,
    /** 2081: Custom saved result that should not be exported from the device. */
    SpectreResultStateDevice = 0x1 | SpectreResultClassStateful | SpectreResultFeatureDevicePrivate,

    /** 4160: Derive a unique binary key. */
    SpectreResultDeriveKey = 0x0 | SpectreResultClassDerive | SpectreResultFeatureAlternate,

    SpectreResultDefaultResult = SpectreResultTemplateLong,
    SpectreResultDefaultLogin = SpectreResultTemplateName,
};

typedef spectre_enum( uint32_t, SpectreCounter ) {
    /** Use a time-based counter value, resulting in a TOTP generator. */
    SpectreCounterTOTP = 0,
    /** The initial value for a site's counter. */
    SpectreCounterInitial = 1,

    SpectreCounterDefault = SpectreCounterInitial,
    SpectreCounterFirst = SpectreCounterTOTP,
    SpectreCounterLast = UINT32_MAX,
};

/** These colours are compatible with the original ANSI SGR. */
typedef spectre_enum( uint8_t, SpectreIdenticonColor ) {
    SpectreIdenticonColorUnset,
    SpectreIdenticonColorRed,
    SpectreIdenticonColorGreen,
    SpectreIdenticonColorYellow,
    SpectreIdenticonColorBlue,
    SpectreIdenticonColorMagenta,
    SpectreIdenticonColorCyan,
    SpectreIdenticonColorMono,

    SpectreIdenticonColorFirst = SpectreIdenticonColorRed,
    SpectreIdenticonColorLast = SpectreIdenticonColorMono,
};

typedef struct {
    const char *leftArm;
    const char *body;
    const char *rightArm;
    const char *accessory;
    SpectreIdenticonColor color;
} SpectreIdenticon;
extern const SpectreIdenticon SpectreIdenticonUnset;

//// Type utilities.

/** Check whether the fingerprint is valid.
 * @return true if the fingerprints represents a fully complete print for a buffer. */
bool spectre_id_valid(const SpectreKeyID *id1);
/** Compare two fingerprints for equality.
 * @return true if the buffers represent identical fingerprints or are both NULL. */
bool spectre_id_equals(const SpectreKeyID *id1, const SpectreKeyID *id2);
/** Encode a fingerprint for a buffer. */
const SpectreKeyID spectre_id_buf(const uint8_t *buf, const size_t size);
/** Reconstruct a fingerprint from its hexadecimal string representation. */
const SpectreKeyID spectre_id_str(const char hex[static 65]);

/**
 * @return The standard identifying name (static) for the given algorithm or NULL if the algorithm is not known.
 */
const char *spectre_algorithm_short_name(const SpectreAlgorithm algorithm);
/**
 * @return The descriptive name (static) for the given algorithm or NULL if the algorithm is not known.
 */
const char *spectre_algorithm_long_name(const SpectreAlgorithm algorithm);

/**
 * @return The purpose represented by the given name or ERR if the name does not represent a known purpose.
 */
const SpectreKeyPurpose spectre_purpose_named(const char *purposeName);
/**
 * @return The standard name (static) for the given purpose or NULL if the purpose is not known.
 */
const char *spectre_purpose_name(const SpectreKeyPurpose purpose);
/**
 * @return The scope identifier (static) to apply when encoding for the given purpose or NULL if the purpose is not known.
 */
const char *spectre_purpose_scope(const SpectreKeyPurpose purpose);

/**
 * @return The result type represented by the given name or ERR if the name does not represent a known type.
 */
const SpectreResultType spectre_type_named(const char *typeName);
/**
 * @return The standard identifying name (static) for the given result type or NULL if the type is not known.
 */
const char *spectre_type_abbreviation(const SpectreResultType resultType);
/**
 * @return The standard identifying name (static) for the given result type or NULL if the type is not known.
 */
const char *spectre_type_short_name(const SpectreResultType resultType);
/**
 * @return The descriptive name (static) for the given result type or NULL if the type is not known.
 */
const char *spectre_type_long_name(const SpectreResultType resultType);

/**
 * @return An array (allocated, count) of strings (static) that express the templates to use for the given type.
 *         NULL if the type is not known or is not a SpectreResultClassTemplate.
 */
const char **spectre_type_templates(const SpectreResultType type, size_t *count);
/**
 * @return A C-string (static) that contains the result encoding template of the given type for a seed that starts with the given byte.
 *         NULL if the type is not known or is not a SpectreResultClassTemplate.
 */
const char *spectre_type_template(const SpectreResultType type, const uint8_t templateIndex);

/**
 * @return A C-string (static) with all the characters in the given character class or NULL if the character class is not known.
 */
const char *spectre_class_characters(const char characterClass);
/**
 * @return A character from given character class that encodes the given byte or NUL if the character class is not known or is empty.
 */
const char spectre_class_character(const char characterClass, const uint8_t seedByte);

#endif // _SPECTRE_TYPES_H
