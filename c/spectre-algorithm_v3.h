// =============================================================================
// Created by Maarten Billemont on 2019-11-27.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

#ifndef _SPECTRE_ALGORITHM_V3_H
#define _SPECTRE_ALGORITHM_V3_H

#include "spectre-algorithm_v2.h"

const char *spectre_type_template_v3(
        SpectreResultType type, uint16_t templateIndex);
const char spectre_class_character_v3(
        char characterClass, uint16_t classIndex);
bool spectre_user_key_v3(
        const SpectreUserKey *userKey, const char *userName, const char *userSecret);
bool spectre_site_key_v3(
        const SpectreSiteKey *siteKey, const SpectreUserKey *userKey, const char *siteName,
        SpectreCounter keyCounter, SpectreKeyPurpose keyPurpose, const char *keyContext);
const char *spectre_site_template_password_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam);
const char *spectre_site_crypted_password_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *cipherText);
const char *spectre_site_derived_password_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *resultParam);
const char *spectre_site_state_v3(
        const SpectreUserKey *userKey, const SpectreSiteKey *siteKey, SpectreResultType resultType, const char *plainText);

#endif // _SPECTRE_ALGORITHM_V3_H
