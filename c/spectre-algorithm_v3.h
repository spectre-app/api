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
