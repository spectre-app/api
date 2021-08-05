// =============================================================================
// Created by Maarten Billemont on 2017-07-15.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================


#include "spectre-marshal.h"
#include "spectre-util.h"
#include "spectre-marshal-util.h"

SPECTRE_LIBS_BEGIN
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
SPECTRE_LIBS_END

static SpectreKeyProviderProxy __spectre_proxy_provider_current = NULL;
static const SpectreUserKey *__spectre_proxy_provider_current_key = NULL;
static SpectreAlgorithm __spectre_proxy_provider_current_algorithm = (SpectreAlgorithm)ERR;
static const char *__spectre_proxy_provider_current_secret = NULL;

static bool __spectre_proxy_provider_secret(const SpectreUserKey **currentKey, SpectreAlgorithm *currentAlgorithm,
        SpectreAlgorithm algorithm, const char *userName) {

    if (!currentKey)
        return spectre_free_string( &__spectre_proxy_provider_current_secret );

    return spectre_update_user_key( currentKey, currentAlgorithm, algorithm, userName, __spectre_proxy_provider_current_secret );
}

static const SpectreUserKey *__spectre_proxy_provider(SpectreAlgorithm algorithm, const char *userName) {

    if (!__spectre_proxy_provider_current)
        return NULL;
    if (!__spectre_proxy_provider_current(
            &__spectre_proxy_provider_current_key, &__spectre_proxy_provider_current_algorithm, algorithm, userName ))
        return NULL;

    return spectre_memdup( __spectre_proxy_provider_current_key, sizeof( *__spectre_proxy_provider_current_key ) );
}

SpectreKeyProvider spectre_proxy_provider_set_secret(const char *userSecret) {

    spectre_proxy_provider_unset();
    __spectre_proxy_provider_current_secret = spectre_strdup( userSecret );
    return spectre_proxy_provider_set( __spectre_proxy_provider_secret );
}

SpectreKeyProvider spectre_proxy_provider_set(const SpectreKeyProviderProxy proxy) {

    spectre_proxy_provider_unset();
    __spectre_proxy_provider_current = proxy;
    return __spectre_proxy_provider;
}

void spectre_proxy_provider_unset() {

    spectre_free( &__spectre_proxy_provider_current_key, sizeof( *__spectre_proxy_provider_current_key ) );
    __spectre_proxy_provider_current_algorithm = (SpectreAlgorithm)ERR;
    if (__spectre_proxy_provider_current) {
        __spectre_proxy_provider_current( NULL, NULL, (SpectreAlgorithm)ERR, NULL );
        __spectre_proxy_provider_current = NULL;
    }
}

void spectre_key_provider_free(SpectreKeyProvider keyProvider) {

    if (keyProvider)
        keyProvider( (SpectreAlgorithm)ERR, NULL );
}

SpectreMarshalledUser *spectre_marshal_user(
        const char *userName, SpectreKeyProvider userKeyProvider, const SpectreAlgorithm algorithmVersion) {

    SpectreMarshalledUser *user;
    if (!userName || !(user = malloc( sizeof( SpectreMarshalledUser ) )))
        return NULL;

    *user = (SpectreMarshalledUser){
            .userKeyProvider = userKeyProvider,
            .algorithm = algorithmVersion,
            .redacted = true,

            .avatar = 0,
            .userName = spectre_strdup( userName ),
            .identicon = SpectreIdenticonUnset,
            .keyID = SpectreKeyIDUnset,
            .defaultType = SpectreResultDefaultResult,
            .loginType = SpectreResultDefaultLogin,
            .loginState = NULL,
            .lastUsed = 0,

            .sites_count = 0,
            .sites = NULL,
    };
    return user;
}

SpectreMarshalledSite *spectre_marshal_site(
        SpectreMarshalledUser *user, const char *siteName, const SpectreResultType resultType,
        const SpectreCounter keyCounter, const SpectreAlgorithm algorithmVersion) {

    if (!siteName)
        return NULL;
    if (!spectre_realloc( &user->sites, NULL, SpectreMarshalledSite, ++user->sites_count )) {
        user->sites_count--;
        return NULL;
    }

    SpectreMarshalledSite *site = &user->sites[user->sites_count - 1];
    *site = (SpectreMarshalledSite){
            .siteName = spectre_strdup( siteName ),
            .algorithm = algorithmVersion,
            .counter = keyCounter,

            .resultType = resultType,
            .resultState = NULL,

            .loginType = SpectreResultNone,
            .loginState = NULL,

            .url = NULL,
            .uses = 0,
            .lastUsed = 0,

            .questions_count = 0,
            .questions = NULL,
    };
    return site;
}

SpectreMarshalledQuestion *spectre_marshal_question(
        SpectreMarshalledSite *site, const char *keyword) {

    if (!spectre_realloc( &site->questions, NULL, SpectreMarshalledQuestion, ++site->questions_count )) {
        site->questions_count--;
        return NULL;
    }
    if (!keyword)
        keyword = "";

    SpectreMarshalledQuestion *question = &site->questions[site->questions_count - 1];
    *question = (SpectreMarshalledQuestion){
            .keyword = spectre_strdup( keyword ),
            .type = SpectreResultTemplatePhrase,
            .state = NULL,
    };
    return question;
}

SpectreMarshalledFile *spectre_marshal_file(
        SpectreMarshalledFile *file, SpectreMarshalledInfo *info, SpectreMarshalledData *data) {

    if (!file) {
        if (!(file = malloc( sizeof( SpectreMarshalledFile ) )))
            return NULL;

        *file = (SpectreMarshalledFile){
                .info = NULL, .data = NULL, .error = (SpectreMarshalError){ .type = SpectreMarshalSuccess, .message = NULL }
        };
    }

    if (data && data != file->data) {
        spectre_marshal_free( &file->data );
        file->data = data;
    }
    if (info && info != file->info) {
        spectre_marshal_free( &file->info );
        file->info = info;
    }

    return file;
}

SpectreMarshalledFile *spectre_marshal_error(
        SpectreMarshalledFile *file, SpectreMarshalErrorType type, const char *format, ...) {

    file = spectre_marshal_file( file, NULL, NULL );
    if (!file)
        return NULL;

    va_list args;
    va_start( args, format );
    file->error = (SpectreMarshalError){ type, spectre_vstr( format, args ) };
    va_end( args );

    return file;
}

void spectre_marshal_info_free(
        SpectreMarshalledInfo **info) {

    if (!info || !*info)
        return;

    spectre_free_strings( &(*info)->userName, NULL );
    spectre_free( info, sizeof( SpectreMarshalledInfo ) );
}

void spectre_marshal_user_free(
        SpectreMarshalledUser **user) {

    if (!user || !*user)
        return;

    spectre_free_strings( &(*user)->userName, NULL );

    for (size_t s = 0; s < (*user)->sites_count; ++s) {
        SpectreMarshalledSite *site = &(*user)->sites[s];
        spectre_free_strings( &site->siteName, &site->resultState, &site->loginState, &site->url, NULL );

        for (size_t q = 0; q < site->questions_count; ++q) {
            SpectreMarshalledQuestion *question = &site->questions[q];
            spectre_free_strings( &question->keyword, &question->state, NULL );
        }
        spectre_free( &site->questions, sizeof( SpectreMarshalledQuestion ) * site->questions_count );
    }

    spectre_free( &(*user)->sites, sizeof( SpectreMarshalledSite ) * (*user)->sites_count );
    spectre_free( user, sizeof( SpectreMarshalledUser ) );
}

void spectre_marshal_data_free(
        SpectreMarshalledData **data) {

    if (!data || !*data)
        return;

    spectre_marshal_data_set_null( *data, NULL );
    spectre_free_string( &(*data)->obj_key );
    spectre_free( data, sizeof( SpectreMarshalledData ) );
}

void spectre_marshal_file_free(
        SpectreMarshalledFile **file) {

    if (!file || !*file)
        return;

    spectre_marshal_free( &(*file)->info );
    spectre_marshal_free( &(*file)->data );
    spectre_free_string( &(*file)->error.message );
    spectre_free( file, sizeof( SpectreMarshalledFile ) );
}

SpectreMarshalledData *spectre_marshal_data_new() {

    SpectreMarshalledData *data = malloc( sizeof( SpectreMarshalledData ) );
    *data = (SpectreMarshalledData){ 0 };
    spectre_marshal_data_set_null( data, NULL );
    data->is_null = false;
    return data;
}

SpectreMarshalledData *spectre_marshal_data_vget(
        SpectreMarshalledData *data, va_list nodes) {

    SpectreMarshalledData *parent = data, *child = parent;
    for (const char *node; parent && (node = va_arg( nodes, const char * )); parent = child) {
        child = NULL;

        for (size_t c = 0; c < parent->children_count; ++c) {
            const char *key = parent->children[c].obj_key;
            if (key && strcmp( node, key ) == OK) {
                child = &parent->children[c];
                break;
            }
        }

        if (!child) {
            if (!spectre_realloc( &parent->children, NULL, SpectreMarshalledData, ++parent->children_count )) {
                --parent->children_count;
                break;
            }
            *(child = &parent->children[parent->children_count - 1]) = (SpectreMarshalledData){ .obj_key = spectre_strdup( node ) };
            spectre_marshal_data_set_null( child, NULL );
            child->is_null = false;
        }
    }

    return child;
}

SpectreMarshalledData *spectre_marshal_data_get(
        SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    SpectreMarshalledData *child = spectre_marshal_data_vget( data, nodes );
    va_end( nodes );

    return child;
}

const SpectreMarshalledData *spectre_marshal_data_vfind(
        const SpectreMarshalledData *data, va_list nodes) {

    const SpectreMarshalledData *parent = data, *child = parent;
    for (const char *node; parent && (node = va_arg( nodes, const char * )); parent = child) {
        child = NULL;

        for (size_t c = 0; c < parent->children_count; ++c) {
            const char *key = parent->children[c].obj_key;
            if (key && strcmp( node, key ) == OK) {
                child = &parent->children[c];
                break;
            }
        }

        if (!child)
            break;
    }

    return child;
}

const SpectreMarshalledData *spectre_marshal_data_find(
        const SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    const SpectreMarshalledData *child = spectre_marshal_data_vfind( data, nodes );
    va_end( nodes );

    return child;
}

bool spectre_marshal_data_vis_null(
        const SpectreMarshalledData *data, va_list nodes) {

    const SpectreMarshalledData *child = spectre_marshal_data_vfind( data, nodes );
    return !child || child->is_null;
}

bool spectre_marshal_data_is_null(
        const SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool value = spectre_marshal_data_vis_null( data, nodes );
    va_end( nodes );

    return value;
}

bool spectre_marshal_data_vset_null(
        SpectreMarshalledData *data, va_list nodes) {

    SpectreMarshalledData *child = spectre_marshal_data_vget( data, nodes );
    if (!child)
        return false;

    spectre_free_string( &child->str_value );
    for (unsigned int c = 0; c < child->children_count; ++c) {
        spectre_marshal_data_set_null( &child->children[c], NULL );
        spectre_free_string( &child->children[c].obj_key );
    }
    spectre_free( &child->children, sizeof( SpectreMarshalledData ) * child->children_count );
    child->children_count = 0;
    child->num_value = NAN;
    child->is_bool = false;
    child->is_null = true;
    return true;
}

bool spectre_marshal_data_set_null(
        SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = spectre_marshal_data_vset_null( data, nodes );
    va_end( nodes );

    return success;
}

bool spectre_marshal_data_vget_bool(
        const SpectreMarshalledData *data, va_list nodes) {

    const SpectreMarshalledData *child = spectre_marshal_data_vfind( data, nodes );
    return child && child->is_bool && child->num_value != false;
}

bool spectre_marshal_data_get_bool(
        const SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool value = spectre_marshal_data_vget_bool( data, nodes );
    va_end( nodes );

    return value;
}

bool spectre_marshal_data_vset_bool(
        const bool value, SpectreMarshalledData *data, va_list nodes) {

    SpectreMarshalledData *child = spectre_marshal_data_vget( data, nodes );
    if (!child || !spectre_marshal_data_set_null( child, NULL ))
        return false;

    child->is_null = false;
    child->is_bool = true;
    child->num_value = value != false;
    return true;
}

bool spectre_marshal_data_set_bool(
        const bool value, SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = spectre_marshal_data_vset_bool( value, data, nodes );
    va_end( nodes );

    return success;
}

double spectre_marshal_data_vget_num(
        const SpectreMarshalledData *data, va_list nodes) {

    const SpectreMarshalledData *child = spectre_marshal_data_vfind( data, nodes );
    return child == NULL? NAN: child->num_value;
}

double spectre_marshal_data_get_num(
        const SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    double value = spectre_marshal_data_vget_num( data, nodes );
    va_end( nodes );

    return value;
}

bool spectre_marshal_data_vset_num(
        const double value, SpectreMarshalledData *data, va_list nodes) {

    SpectreMarshalledData *child = spectre_marshal_data_vget( data, nodes );
    if (!child || !spectre_marshal_data_set_null( child, NULL ))
        return false;

    child->is_null = false;
    child->num_value = value;
    child->str_value = spectre_str( "%g", value );
    return true;
}

bool spectre_marshal_data_set_num(
        const double value, SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = spectre_marshal_data_vset_num( value, data, nodes );
    va_end( nodes );

    return success;
}

const char *spectre_marshal_data_vget_str(
        const SpectreMarshalledData *data, va_list nodes) {

    const SpectreMarshalledData *child = spectre_marshal_data_vfind( data, nodes );
    return child == NULL? NULL: child->str_value;
}

const char *spectre_marshal_data_get_str(
        const SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    const char *value = spectre_marshal_data_vget_str( data, nodes );
    va_end( nodes );

    return value;
}

bool spectre_marshal_data_vset_str(
        const char *value, SpectreMarshalledData *data, va_list nodes) {

    SpectreMarshalledData *child = spectre_marshal_data_vget( data, nodes );
    if (!child || !spectre_marshal_data_set_null( child, NULL ))
        return false;

    if (value) {
        child->is_null = false;
        child->str_value = spectre_strdup( value );
    }

    return true;
}

bool spectre_marshal_data_set_str(
        const char *value, SpectreMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = spectre_marshal_data_vset_str( value, data, nodes );
    va_end( nodes );

    return success;
}

void spectre_marshal_data_filter(
        SpectreMarshalledData *data, bool (*filter)(SpectreMarshalledData *, void *), void *args) {

    size_t children_count = 0;
    SpectreMarshalledData *children = NULL;

    for (size_t c = 0; c < data->children_count; ++c) {
        SpectreMarshalledData *child = &data->children[c];
        if (filter( child, args )) {
            // Valid child in this object, keep it.
            ++children_count;

            if (children) {
                if (!spectre_realloc( &children, NULL, SpectreMarshalledData, children_count )) {
                    --children_count;
                    continue;
                }
                child->arr_index = children_count - 1;
                children[child->arr_index] = *child;
            }
        }
        else {
            // Not a valid child in this object, remove it.
            spectre_marshal_data_set_null( child, NULL );
            spectre_free_string( &child->obj_key );

            if (!children)
                children = spectre_memdup( data->children, sizeof( SpectreMarshalledData ) * children_count );
        }
    }

    if (children) {
        spectre_free( &data->children, sizeof( SpectreMarshalledData ) * data->children_count );
        data->children = children;
        data->children_count = children_count;
    }
}

bool spectre_marshal_data_filter_empty(
        __unused SpectreMarshalledData *child, __unused void *args) {

    return false;
}

static const char *spectre_marshal_write_flat(
        SpectreMarshalledFile *file) {

    const SpectreMarshalledData *data = file->data;
    if (!data) {
        spectre_marshal_error( file, SpectreMarshalErrorMissing,
                "Missing data." );
        return NULL;
    }

    char *out = NULL;
    spectre_string_pushf( &out, "# Spectre site export\n" );
    spectre_string_pushf( &out, spectre_marshal_data_get_bool( data, "export", "redacted", NULL )?
                                "#     Export of site names and stored passwords (unless device-private) encrypted with the user key.\n":
                                "#     Export of site names and passwords in clear-text.\n" );
    spectre_string_pushf( &out, "# \n" );
    spectre_string_pushf( &out, "##\n" );
    spectre_string_pushf( &out, "# Format: %d\n", 1 );

    const char *out_date = spectre_default( "", spectre_marshal_data_get_str( data, "export", "date", NULL ) );
    const char *out_fullName = spectre_default( "", spectre_marshal_data_get_str( data, "user", "full_name", NULL ) );
    unsigned int out_avatar = (unsigned int)spectre_marshal_data_get_num( data, "user", "avatar", NULL );
    const char *out_identicon = spectre_default( "", spectre_marshal_data_get_str( data, "user", "identicon", NULL ) );
    const char *out_keyID = spectre_default( "", spectre_marshal_data_get_str( data, "user", "key_id", NULL ) );
    SpectreAlgorithm out_algorithm = (SpectreAlgorithm)spectre_marshal_data_get_num( data, "user", "algorithm", NULL );
    SpectreResultType out_defaultType = (SpectreResultType)spectre_marshal_data_get_num( data, "user", "default_type", NULL );
    bool out_redacted = spectre_marshal_data_get_bool( data, "export", "redacted", NULL );

    spectre_string_pushf( &out, "# Date: %s\n", out_date );
    spectre_string_pushf( &out, "# User Name: %s\n", out_fullName );
    spectre_string_pushf( &out, "# Full Name: %s\n", out_fullName );
    spectre_string_pushf( &out, "# Avatar: %u\n", out_avatar );
    spectre_string_pushf( &out, "# Identicon: %s\n", out_identicon );
    spectre_string_pushf( &out, "# Key ID: %s\n", out_keyID );
    spectre_string_pushf( &out, "# Algorithm: %d\n", out_algorithm );
    spectre_string_pushf( &out, "# Default Type: %d\n", out_defaultType );
    spectre_string_pushf( &out, "# Passwords: %s\n", out_redacted? "PROTECTED": "VISIBLE" );
    spectre_string_pushf( &out, "##\n" );
    spectre_string_pushf( &out, "#\n" );
    spectre_string_pushf( &out, "#%19s  %8s  %8s  %25s\t%25s\t%s\n", "Last", "Times", "Password", "Login", "Site", "Site" );
    spectre_string_pushf( &out, "#%19s  %8s  %8s  %25s\t%25s\t%s\n", "used", "used", "type", "name", "name", "password" );

    // Sites.
    const char *typeString;
    const SpectreMarshalledData *sites = spectre_marshal_data_find( data, "sites", NULL );
    for (size_t s = 0; s < (sites? sites->children_count: 0); ++s) {
        const SpectreMarshalledData *site = &sites->children[s];
        spectre_string_pushf( &out, "%s  %8ld  %8s  %25s\t%25s\t%s\n",
                spectre_default( "", spectre_marshal_data_get_str( site, "last_used", NULL ) ),
                (long)spectre_marshal_data_get_num( site, "uses", NULL ),
                typeString = spectre_str( "%lu:%lu:%lu",
                        (long)spectre_marshal_data_get_num( site, "type", NULL ),
                        (long)spectre_marshal_data_get_num( site, "algorithm", NULL ),
                        (long)spectre_marshal_data_get_num( site, "counter", NULL ) ),
                spectre_default( "", spectre_marshal_data_get_str( site, "login_name", NULL ) ),
                site->obj_key,
                spectre_default( "", spectre_marshal_data_get_str( site, "password", NULL ) ) );
        spectre_free_string( &typeString );
    }

    if (!out)
        spectre_marshal_error( file, SpectreMarshalErrorFormat,
                "Couldn't encode JSON." );
    else
        spectre_marshal_error( file, SpectreMarshalSuccess, NULL );

    return out;
}

#if SPECTRE_JSON

static json_object *spectre_get_json_data(
        const SpectreMarshalledData *data) {

    if (!data || data->is_null)
        return NULL;
    if (data->is_bool)
        return json_object_new_boolean( data->num_value != false );
    if (!isnan( data->num_value )) {
        if (data->str_value)
            return json_object_new_double_s( data->num_value, data->str_value );
        else
            return json_object_new_double( data->num_value );
    }
    if (data->str_value)
        return json_object_new_string( data->str_value );

    json_object *obj = NULL;
    for (size_t c = 0; c < data->children_count; ++c) {
        SpectreMarshalledData *child = &data->children[c];
        if (!obj) {
            if (child->obj_key)
                obj = json_object_new_object();
            else
                obj = json_object_new_array();
        }

        json_object *child_obj = spectre_get_json_data( child );
        if (json_object_is_type( obj, json_type_array ))
            json_object_array_add( obj, child_obj );
        else if (child_obj && !(json_object_is_type( child_obj, json_type_object ) && json_object_object_length( child_obj ) == 0))
            // We omit keys that map to null or empty object values.
            json_object_object_add( obj, child->obj_key, child_obj );
        else
            json_object_put( child_obj );
    }

    return obj;
}

static const char *spectre_marshal_write_json(
        SpectreMarshalledFile *file) {

    json_object *json_file = spectre_get_json_data( file->data );
    if (!json_file) {
        spectre_marshal_error( file, SpectreMarshalErrorFormat,
                "Couldn't serialize export data." );
        return NULL;
    }

    json_object *json_export = spectre_get_json_object( json_file, "export", true );
    json_object_object_add( json_export, "format", json_object_new_int( 2 ) );

    const char *out = spectre_strdup( json_object_to_json_string_ext( json_file,
            JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_NOSLASHESCAPE ) );
    json_object_put( json_file );

    if (!out)
        spectre_marshal_error( file, SpectreMarshalErrorFormat,
                "Couldn't encode JSON." );
    else
        spectre_marshal_error( file, SpectreMarshalSuccess, NULL );

    return out;
}

#endif

static bool spectre_marshal_data_filter_site_exists(
        SpectreMarshalledData *child, void *args) {

    SpectreMarshalledUser *user = args;

    for (size_t s = 0; s < user->sites_count; ++s) {
        if (strcmp( (&user->sites[s])->siteName, child->obj_key ) == OK)
            return true;
    }

    return false;
}

static bool spectre_marshal_data_filter_question_exists(
        SpectreMarshalledData *child, void *args) {

    SpectreMarshalledSite *site = args;

    for (size_t s = 0; s < site->questions_count; ++s) {
        if (strcmp( (&site->questions[s])->keyword, child->obj_key ) == OK)
            return true;
    }

    return false;
}

const char *spectre_marshal_write(
        const SpectreFormat outFormat, SpectreMarshalledFile **file_, SpectreMarshalledUser *user) {

    SpectreMarshalledFile *file = file_? *file_: NULL;
    file = spectre_marshal_file( file, NULL, file && file->data? file->data: spectre_marshal_data_new() );
    if (file_)
        *file_ = file;
    if (!file)
        return NULL;
    if (!file->data) {
        if (!file_)
            spectre_marshal_free( &file );
        else
            spectre_marshal_error( file, SpectreMarshalErrorInternal,
                    "Couldn't allocate data." );
        return NULL;
    }
    spectre_marshal_error( file, SpectreMarshalSuccess, NULL );

    if (user) {
        if (!user->userName || !strlen( user->userName )) {
            if (!file_)
                spectre_marshal_free( &file );
            else
                spectre_marshal_error( file, SpectreMarshalErrorMissing,
                        "Missing user name." );
            return NULL;
        }

        const SpectreUserKey *userKey = NULL;
        if (user->userKeyProvider)
            userKey = user->userKeyProvider( user->algorithm, user->userName );

        // Section: "export"
        SpectreMarshalledData *data_export = spectre_marshal_data_get( file->data, "export", NULL );
        char dateString[21];
        time_t now = time( NULL );
        if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &now ) ))
            spectre_marshal_data_set_str( dateString, data_export, "date", NULL );
        spectre_marshal_data_set_bool( user->redacted, data_export, "redacted", NULL );

        // Section: "user"
        const char *loginState = NULL;
        if (!user->redacted) {
            // Clear Text
            spectre_free( &userKey, sizeof( *userKey ) );
            if (!user->userKeyProvider || !(userKey = user->userKeyProvider( user->algorithm, user->userName ))) {
                if (!file_)
                    spectre_marshal_free( &file );
                else
                    spectre_marshal_error( file, SpectreMarshalErrorInternal,
                            "Couldn't derive user key." );
                return NULL;
            }

            loginState = spectre_site_result( userKey, user->userName, user->loginType, user->loginState,
                    SpectreCounterInitial, SpectreKeyPurposeIdentification, NULL );
        }
        else {
            // Redacted
            if (user->loginType & SpectreResultFeatureExportContent && user->loginState && strlen( user->loginState ))
                loginState = spectre_strdup( user->loginState );
        }

        const char *identiconString = spectre_identicon_encode( user->identicon );
        SpectreMarshalledData *data_user = spectre_marshal_data_get( file->data, "user", NULL );
        spectre_marshal_data_set_num( user->avatar, data_user, "avatar", NULL );
        spectre_marshal_data_set_str( user->userName, data_user, "full_name", NULL );
        spectre_marshal_data_set_str( identiconString, data_user, "identicon", NULL );
        spectre_marshal_data_set_num( user->algorithm, data_user, "algorithm", NULL );
        spectre_marshal_data_set_str( user->keyID.hex, data_user, "key_id", NULL );
        spectre_marshal_data_set_num( user->defaultType, data_user, "default_type", NULL );
        spectre_marshal_data_set_num( user->loginType, data_user, "login_type", NULL );
        spectre_marshal_data_set_str( loginState, data_user, "login_name", NULL );
        if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &user->lastUsed ) ))
            spectre_marshal_data_set_str( dateString, data_user, "last_used", NULL );
        spectre_free_strings( &identiconString, &loginState, NULL );

        // Section "sites"
        SpectreMarshalledData *data_sites = spectre_marshal_data_get( file->data, "sites", NULL );
        spectre_marshal_data_filter( data_sites, spectre_marshal_data_filter_site_exists, user );
        for (size_t s = 0; s < user->sites_count; ++s) {
            SpectreMarshalledSite *site = &user->sites[s];
            if (!site->siteName || !strlen( site->siteName ))
                continue;

            const char *resultState = NULL;
            if (!user->redacted) {
                // Clear Text
                spectre_free( &userKey, sizeof( *userKey ) );
                if (!user->userKeyProvider || !(userKey = user->userKeyProvider( site->algorithm, user->userName ))) {
                    if (!file_)
                        spectre_marshal_free( &file );
                    else
                        spectre_marshal_error( file, SpectreMarshalErrorInternal,
                                "Couldn't derive user key." );
                    return NULL;
                }

                resultState = spectre_site_result( userKey, site->siteName,
                        site->resultType, site->resultState, site->counter, SpectreKeyPurposeAuthentication, NULL );
                loginState = spectre_site_result( userKey, site->siteName,
                        site->loginType, site->loginState, SpectreCounterInitial, SpectreKeyPurposeIdentification, NULL );
            }
            else {
                // Redacted
                if (site->resultType & SpectreResultFeatureExportContent && site->resultState && strlen( site->resultState ))
                    resultState = spectre_strdup( site->resultState );
                if (site->loginType & SpectreResultFeatureExportContent && site->loginState && strlen( site->loginState ))
                    loginState = spectre_strdup( site->loginState );
            }

            spectre_marshal_data_set_num( site->counter, data_sites, site->siteName, "counter", NULL );
            spectre_marshal_data_set_num( site->algorithm, data_sites, site->siteName, "algorithm", NULL );
            spectre_marshal_data_set_num( site->resultType, data_sites, site->siteName, "type", NULL );
            spectre_marshal_data_set_str( resultState, data_sites, site->siteName, "password", NULL );
            spectre_marshal_data_set_num( site->loginType, data_sites, site->siteName, "login_type", NULL );
            spectre_marshal_data_set_str( loginState, data_sites, site->siteName, "login_name", NULL );
            spectre_marshal_data_set_num( site->uses, data_sites, site->siteName, "uses", NULL );
            if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &site->lastUsed ) ))
                spectre_marshal_data_set_str( dateString, data_sites, site->siteName, "last_used", NULL );

            SpectreMarshalledData *data_questions = spectre_marshal_data_get( file->data, "sites", site->siteName, "questions", NULL );
            spectre_marshal_data_filter( data_questions, spectre_marshal_data_filter_question_exists, site );
            for (size_t q = 0; q < site->questions_count; ++q) {
                SpectreMarshalledQuestion *question = &site->questions[q];
                if (!question->keyword)
                    continue;

                const char *answer = NULL;
                if (!user->redacted) {
                    // Clear Text
                    answer = spectre_site_result( userKey, site->siteName,
                            question->type, question->state, SpectreCounterInitial, SpectreKeyPurposeRecovery, question->keyword );
                }
                else {
                    // Redacted
                    if (question->state && strlen( question->state ) && site->resultType & SpectreResultFeatureExportContent)
                        answer = spectre_strdup( question->state );
                }

                spectre_marshal_data_set_num( question->type, data_questions, question->keyword, "type", NULL );
                spectre_marshal_data_set_str( answer, data_questions, question->keyword, "answer", NULL );
                spectre_free_strings( &answer, NULL );
            }

            spectre_marshal_data_set_str( site->url, data_sites, site->siteName, "_ext_spectre", "url", NULL );
            spectre_free_strings( &resultState, &loginState, NULL );
        }
    }

    const char *out = NULL;
    switch (outFormat) {
        case SpectreFormatNone:
            spectre_marshal_error( file, SpectreMarshalSuccess, NULL );
            break;
        case SpectreFormatFlat:
            out = spectre_marshal_write_flat( file );
            break;
#if SPECTRE_JSON
        case SpectreFormatJSON:
            out = spectre_marshal_write_json( file );
            break;
#endif
        default:
            spectre_marshal_error( file, SpectreMarshalErrorFormat,
                    "Unsupported output format: %u", outFormat );
            break;
    }
    if (out && file->error.type == SpectreMarshalSuccess)
        file = spectre_marshal_read( file, out );
    if (file_)
        *file_ = file;
    else
        spectre_marshal_free( &file );

    return out;
}

static void spectre_marshal_read_flat(
        SpectreMarshalledFile *file, const char *in) {

    if (!file)
        return;

    spectre_marshal_file( file, NULL, spectre_marshal_data_new() );
    if (!file->data) {
        spectre_marshal_error( file, SpectreMarshalErrorInternal,
                "Couldn't allocate data." );
        return;
    }

    // Parse import data.
    unsigned int format = 0, avatar = 0;
    const char *userName = NULL, *keyID = NULL;
    SpectreAlgorithm algorithm = SpectreAlgorithmCurrent;
    SpectreIdenticon identicon = SpectreIdenticonUnset;
    SpectreResultType defaultType = SpectreResultDefaultResult;
    time_t exportDate = 0;
    bool headerStarted = false, headerEnded = false, importRedacted = false;
    for (const char *endOfLine, *positionInLine = in; (endOfLine = strstr( positionInLine, "\n" )); positionInLine = endOfLine + 1) {

        // Comment or header
        if (*positionInLine == '#') {
            ++positionInLine;

            if (!headerStarted) {
                if (*positionInLine == '#')
                    // ## starts header
                    headerStarted = true;
                // Comment before header
                continue;
            }
            if (headerEnded)
                // Comment after header
                continue;
            if (*positionInLine == '#') {
                // ## ends header
                headerEnded = true;

                char dateString[21];
                const char *identiconString = spectre_identicon_encode( identicon );

                if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &exportDate ) )) {
                    spectre_marshal_data_set_str( dateString, file->data, "export", "date", NULL );
                    spectre_marshal_data_set_str( dateString, file->data, "user", "last_used", NULL );
                }
                spectre_marshal_data_set_num( algorithm, file->data, "user", "algorithm", NULL );
                spectre_marshal_data_set_bool( importRedacted, file->data, "export", "redacted", NULL );
                spectre_marshal_data_set_num( avatar, file->data, "user", "avatar", NULL );
                spectre_marshal_data_set_str( userName, file->data, "user", "full_name", NULL );
                spectre_marshal_data_set_str( identiconString, file->data, "user", "identicon", NULL );
                spectre_marshal_data_set_str( keyID, file->data, "user", "key_id", NULL );
                spectre_marshal_data_set_num( defaultType, file->data, "user", "default_type", NULL );
                spectre_free_string( &identiconString );
                continue;
            }

            // Header
            const char *line = positionInLine;
            const char *headerName = spectre_get_token( &positionInLine, endOfLine, ":\n" );
            const char *headerValue = spectre_get_token( &positionInLine, endOfLine, "\n" );
            if (!headerName || !headerValue) {
                spectre_marshal_error( file, SpectreMarshalErrorStructure,
                        "Invalid header: %s", spectre_strndup( line, (size_t)(endOfLine - line) ) );
                spectre_free_strings( &headerName, &headerValue, NULL );
                continue;
            }

            if (spectre_strcasecmp( headerName, "Format" ) == OK)
                format = (unsigned int)strtoul( headerValue, NULL, 10 );
            if (spectre_strcasecmp( headerName, "Date" ) == OK)
                exportDate = spectre_get_timegm( headerValue );
            if (spectre_strcasecmp( headerName, "Passwords" ) == OK)
                importRedacted = spectre_strcasecmp( headerValue, "VISIBLE" ) != OK;
            if (spectre_strcasecmp( headerName, "Algorithm" ) == OK) {
                unsigned long value = strtoul( headerValue, NULL, 10 );
                if (value < SpectreAlgorithmFirst || value > SpectreAlgorithmLast)
                    spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                            "Invalid user algorithm version: %s", headerValue );
                else
                    algorithm = (SpectreAlgorithm)value;
            }
            if (spectre_strcasecmp( headerName, "Avatar" ) == OK)
                avatar = (unsigned int)strtoul( headerValue, NULL, 10 );
            if (spectre_strcasecmp( headerName, "Full Name" ) == OK || spectre_strcasecmp( headerName, "User Name" ) == OK)
                userName = spectre_strdup( headerValue );
            if (spectre_strcasecmp( headerName, "Identicon" ) == OK)
                identicon = spectre_identicon_encoded( headerValue );
            if (spectre_strcasecmp( headerName, "Key ID" ) == OK)
                keyID = spectre_strdup( headerValue );
            if (spectre_strcasecmp( headerName, "Default Type" ) == OK) {
                unsigned long value = strtoul( headerValue, NULL, 10 );
                if (!spectre_type_short_name( (SpectreResultType)value ))
                    spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                            "Invalid user default type: %s", headerValue );
                else
                    defaultType = (SpectreResultType)value;
            }

            spectre_free_strings( &headerName, &headerValue, NULL );
            continue;
        }
        if (!headerEnded)
            continue;
        if (!userName)
            spectre_marshal_error( file, SpectreMarshalErrorMissing,
                    "Missing header: Full Name" );
        if (positionInLine >= endOfLine)
            continue;

        // Site
        const char *siteName = NULL, *siteResultState = NULL, *siteLoginState = NULL;
        const char *str_lastUsed = NULL, *str_uses = NULL, *str_type = NULL, *str_algorithm = NULL, *str_counter = NULL;
        switch (format) {
            case 0: {
                str_lastUsed = spectre_get_token( &positionInLine, endOfLine, " \t\n" );
                str_uses = spectre_get_token( &positionInLine, endOfLine, " \t\n" );
                char *typeAndVersion = (char *)spectre_get_token( &positionInLine, endOfLine, " \t\n" );
                if (typeAndVersion) {
                    str_type = spectre_strdup( strtok( typeAndVersion, ":" ) );
                    str_algorithm = spectre_strdup( strtok( NULL, "" ) );
                    spectre_free_string( &typeAndVersion );
                }
                str_counter = spectre_str( "%u", SpectreCounterDefault );
                siteLoginState = NULL;
                siteName = spectre_get_token( &positionInLine, endOfLine, "\t\n" );
                siteResultState = spectre_get_token( &positionInLine, endOfLine, "\n" );
                break;
            }
            case 1: {
                str_lastUsed = spectre_get_token( &positionInLine, endOfLine, " \t\n" );
                str_uses = spectre_get_token( &positionInLine, endOfLine, " \t\n" );
                char *typeAndVersionAndCounter = (char *)spectre_get_token( &positionInLine, endOfLine, " \t\n" );
                if (typeAndVersionAndCounter) {
                    str_type = spectre_strdup( strtok( typeAndVersionAndCounter, ":" ) );
                    str_algorithm = spectre_strdup( strtok( NULL, ":" ) );
                    str_counter = spectre_strdup( strtok( NULL, "" ) );
                    spectre_free_string( &typeAndVersionAndCounter );
                }
                siteLoginState = spectre_get_token( &positionInLine, endOfLine, "\t\n" );
                siteName = spectre_get_token( &positionInLine, endOfLine, "\t\n" );
                siteResultState = spectre_get_token( &positionInLine, endOfLine, "\n" );
                break;
            }
            default: {
                spectre_marshal_error( file, SpectreMarshalErrorFormat,
                        "Unexpected import format: %u", format );
                continue;
            }
        }

        if (siteName && str_type && str_counter && str_algorithm && str_uses && str_lastUsed) {
            SpectreResultType siteResultType = (SpectreResultType)strtoul( str_type, NULL, 10 );
            if (!spectre_type_short_name( siteResultType )) {
                spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                        "Invalid site type: %s: %s", siteName, str_type );
                continue;
            }
            long long int value = strtoll( str_counter, NULL, 10 );
            if (value < SpectreCounterFirst || value > SpectreCounterLast) {
                spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                        "Invalid site counter: %s: %s", siteName, str_counter );
                continue;
            }
            SpectreCounter siteKeyCounter = (SpectreCounter)value;
            value = strtoll( str_algorithm, NULL, 0 );
            if (value < SpectreAlgorithmFirst || value > SpectreAlgorithmLast) {
                spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                        "Invalid site algorithm: %s: %s", siteName, str_algorithm );
                continue;
            }
            SpectreAlgorithm siteAlgorithm = (SpectreAlgorithm)value;
            time_t siteLastUsed = spectre_get_timegm( str_lastUsed );
            if (!siteLastUsed) {
                spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                        "Invalid site last used: %s: %s", siteName, str_lastUsed );
                continue;
            }
            SpectreResultType siteLoginType = siteLoginState && *siteLoginState? SpectreResultStatePersonal: SpectreResultNone;

            char dateString[21];
            spectre_marshal_data_set_num( siteAlgorithm, file->data, "sites", siteName, "algorithm", NULL );
            spectre_marshal_data_set_num( siteKeyCounter, file->data, "sites", siteName, "counter", NULL );
            spectre_marshal_data_set_num( siteResultType, file->data, "sites", siteName, "type", NULL );
            spectre_marshal_data_set_str( siteResultState, file->data, "sites", siteName, "password", NULL );
            spectre_marshal_data_set_num( siteLoginType, file->data, "sites", siteName, "login_type", NULL );
            spectre_marshal_data_set_str( siteLoginState, file->data, "sites", siteName, "login_name", NULL );
            spectre_marshal_data_set_num( strtol( str_uses, NULL, 10 ), file->data, "sites", siteName, "uses", NULL );
            if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &siteLastUsed ) ))
                spectre_marshal_data_set_str( dateString, file->data, "sites", siteName, "last_used", NULL );
        }
        else {
            spectre_marshal_error( file, SpectreMarshalErrorMissing,
                    "Missing one of: lastUsed=%s, uses=%s, type=%s, version=%s, counter=%s, loginName=%s, siteName=%s",
                    str_lastUsed, str_uses, str_type, str_algorithm, str_counter, siteLoginState, siteName );
            continue;
        }

        spectre_free_strings( &str_lastUsed, &str_uses, &str_type, &str_algorithm, &str_counter, NULL );
        spectre_free_strings( &siteLoginState, &siteName, &siteResultState, NULL );
    }
    spectre_free_strings( &userName, &keyID, NULL );
}

#if SPECTRE_JSON

static void spectre_marshal_read_json(
        SpectreMarshalledFile *file, const char *in) {

    if (!file)
        return;

    spectre_marshal_file( file, NULL, spectre_marshal_data_new() );
    if (!file->data) {
        spectre_marshal_error( file, SpectreMarshalErrorInternal,
                "Couldn't allocate data." );
        return;
    }

    // Parse import data.
    enum json_tokener_error json_error = json_tokener_success;
    json_object *json_file = json_tokener_parse_verbose( in, &json_error );
    if (!json_file || json_error != json_tokener_success) {
        spectre_marshal_error( file, SpectreMarshalErrorFormat,
                "Couldn't parse JSON: %s", json_tokener_error_desc( json_error ) );
        return;
    }

    spectre_set_json_data( file->data, json_file );
    json_object_put( json_file );

    // version 1 fixes:
    if (spectre_marshal_data_get_num( file->data, "export", "format", NULL ) == 1) {
        SpectreMarshalledData *sites = (SpectreMarshalledData *)spectre_marshal_data_find( file->data, "sites", NULL );

        // - default login_type "name" written to file, preventing adoption of user-level standard login_type.
        for (size_t s = 0; s < (sites? sites->children_count: 0); ++s) {
            SpectreMarshalledData *site = &sites->children[s];
            if (spectre_marshal_data_get_num( site, "login_type", NULL ) == SpectreResultTemplateName)
                spectre_marshal_data_set_null( site, "login_type", NULL );
        }
    }

    return;
}

#endif

SpectreMarshalledFile *spectre_marshal_read(
        SpectreMarshalledFile *file, const char *in) {

    SpectreMarshalledInfo *info = malloc( sizeof( SpectreMarshalledInfo ) );
    file = spectre_marshal_file( file, info, NULL );
    if (!file)
        return NULL;

    spectre_marshal_error( file, SpectreMarshalSuccess, NULL );
    if (!info) {
        spectre_marshal_error( file, SpectreMarshalErrorInternal,
                "Couldn't allocate info." );
        return file;
    }

    *info = (SpectreMarshalledInfo){ .format = SpectreFormatNone, .identicon = SpectreIdenticonUnset };
    if (in && strlen( in )) {
        if (in[0] == '#') {
            info->format = SpectreFormatFlat;
            spectre_marshal_read_flat( file, in );
        }
        else if (in[0] == '{') {
            info->format = SpectreFormatJSON;
#if SPECTRE_JSON
            spectre_marshal_read_json( file, in );
#else
            spectre_marshal_error( file, SpectreMarshalErrorFormat,
                    "JSON support is not enabled." );
#endif
        }
    }

    // Section: "export"
    info->exportDate = spectre_get_timegm( spectre_marshal_data_get_str( file->data, "export", "date", NULL ) );
    info->redacted = spectre_marshal_data_get_bool( file->data, "export", "redacted", NULL )
                     || spectre_marshal_data_is_null( file->data, "export", "redacted", NULL );

    // Section: "user"
    info->algorithm = spectre_default_num( SpectreAlgorithmCurrent, spectre_marshal_data_get_num( file->data, "user", "algorithm", NULL ) );
    info->avatar = spectre_default_num( 0U, spectre_marshal_data_get_num( file->data, "user", "avatar", NULL ) );
    info->userName = spectre_strdup( spectre_marshal_data_get_str( file->data, "user", "full_name", NULL ) );
    info->identicon = spectre_identicon_encoded( spectre_marshal_data_get_str( file->data, "user", "identicon", NULL ) );
    info->keyID = spectre_id_str( spectre_marshal_data_get_str( file->data, "user", "key_id", NULL ) );
    info->lastUsed = spectre_get_timegm( spectre_marshal_data_get_str( file->data, "user", "last_used", NULL ) );

    return file;
}

SpectreMarshalledUser *spectre_marshal_auth(
        SpectreMarshalledFile *file, const SpectreKeyProvider userKeyProvider) {

    if (!file)
        return NULL;

    spectre_marshal_error( file, SpectreMarshalSuccess, NULL );
    if (!file->info) {
        spectre_marshal_error( file, SpectreMarshalErrorMissing,
                "File wasn't parsed yet." );
        return NULL;
    }
    if (!file->data) {
        spectre_marshal_error( file, SpectreMarshalErrorMissing,
                "No input data." );
        return NULL;
    }
    const SpectreMarshalledData *userData = spectre_marshal_data_find( file->data, "user", NULL );
    if (!userData) {
        spectre_marshal_error( file, SpectreMarshalErrorMissing,
                "Missing user data." );
        return NULL;
    }

    // Section: "user"
    bool fileRedacted = spectre_marshal_data_get_bool( file->data, "export", "redacted", NULL )
                        || spectre_marshal_data_is_null( file->data, "export", "redacted", NULL );

    SpectreAlgorithm algorithm = spectre_default_num( SpectreAlgorithmCurrent,
            spectre_marshal_data_get_num( userData, "algorithm", NULL ) );
    if (algorithm < SpectreAlgorithmFirst || algorithm > SpectreAlgorithmLast) {
        spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                "Invalid user algorithm: %u", algorithm );
        return NULL;
    }

    unsigned int avatar = spectre_default_num( 0U,
            spectre_marshal_data_get_num( userData, "avatar", NULL ) );

    const char *userName = spectre_marshal_data_get_str( userData, "full_name", NULL );
    if (!userName || !strlen( userName )) {
        spectre_marshal_error( file, SpectreMarshalErrorMissing,
                "Missing value for user name." );
        return NULL;
    }

    SpectreIdenticon identicon = spectre_identicon_encoded( spectre_marshal_data_get_str( userData, "identicon", NULL ) );

    SpectreKeyID keyID = spectre_id_str( spectre_marshal_data_get_str( userData, "key_id", NULL ) );

    SpectreResultType defaultType = spectre_default_num( SpectreResultDefaultResult,
            spectre_marshal_data_get_num( userData, "default_type", NULL ) );
    if (!spectre_type_short_name( defaultType )) {
        spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                "Invalid user default type: %u", defaultType );
        return NULL;
    }

    SpectreResultType loginType = spectre_default_num( SpectreResultDefaultLogin,
            spectre_marshal_data_get_num( userData, "login_type", NULL ) );
    if (!spectre_type_short_name( loginType )) {
        spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                "Invalid user login type: %u", loginType );
        return NULL;
    }

    const char *loginState = spectre_marshal_data_get_str( userData, "login_name", NULL );

    const char *str_lastUsed = spectre_marshal_data_get_str( userData, "last_used", NULL );

    time_t lastUsed = spectre_get_timegm( str_lastUsed );
    if (!lastUsed) {
        spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                "Invalid user last used: %s", str_lastUsed );
        return NULL;
    }

    const SpectreUserKey *userKey = NULL;
    if (userKeyProvider && !(userKey = userKeyProvider( algorithm, userName ))) {
        spectre_marshal_error( file, SpectreMarshalErrorInternal,
                "Couldn't derive user key." );
        return NULL;
    }
    if (userKey && !spectre_id_equals( &keyID, &userKey->keyID )) {
        spectre_marshal_error( file, SpectreMarshalErrorUserSecret,
                "User key: %s, doesn't match keyID: %s.", userKey->keyID.hex, keyID.hex );
        spectre_free( &userKey, sizeof( *userKey ) );
        return NULL;
    }

    SpectreMarshalledUser *user = NULL;
    if (!(user = spectre_marshal_user( userName, userKeyProvider, algorithm ))) {
        spectre_marshal_error( file, SpectreMarshalErrorInternal,
                "Couldn't allocate a new user." );
        spectre_free( &userKey, sizeof( *userKey ) );
        spectre_marshal_free( &user );
        return NULL;
    }

    user->redacted = fileRedacted;
    user->avatar = avatar;
    user->identicon = identicon;
    user->keyID = keyID;
    user->defaultType = defaultType;
    user->loginType = loginType;
    user->lastUsed = lastUsed;

    if (!user->redacted) {
        // Clear Text
        spectre_free( &userKey, sizeof( *userKey ) );
        if (!userKeyProvider || !(userKey = userKeyProvider( user->algorithm, user->userName ))) {
            spectre_marshal_error( file, SpectreMarshalErrorInternal,
                    "Couldn't derive user key." );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }

        if (loginState && strlen( loginState ) && userKey)
            user->loginState = spectre_site_state( userKey, user->userName, user->loginType, loginState,
                    SpectreCounterInitial, SpectreKeyPurposeIdentification, NULL );
    }
    else {
        // Redacted
        if (loginState && strlen( loginState ))
            user->loginState = spectre_strdup( loginState );
    }

    // Section "sites"
    const SpectreMarshalledData *sitesData = spectre_marshal_data_find( file->data, "sites", NULL );
    for (size_t s = 0; s < (sitesData? sitesData->children_count: 0); ++s) {
        const SpectreMarshalledData *siteData = &sitesData->children[s];
        const char *siteName = siteData->obj_key;

        algorithm = spectre_default_num( user->algorithm,
                spectre_marshal_data_get_num( siteData, "algorithm", NULL ) );
        if (algorithm < SpectreAlgorithmFirst || algorithm > SpectreAlgorithmLast) {
            spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                    "Invalid site algorithm: %s: %u", siteName, algorithm );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }
        SpectreCounter siteCounter = spectre_default_num( SpectreCounterDefault,
                spectre_marshal_data_get_num( siteData, "counter", NULL ) );
        if (siteCounter < SpectreCounterFirst || siteCounter > SpectreCounterLast) {
            spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                    "Invalid site result counter: %s: %d", siteName, siteCounter );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }
        SpectreResultType siteResultType = spectre_default_num( user->defaultType,
                spectre_marshal_data_get_num( siteData, "type", NULL ) );
        if (!spectre_type_short_name( siteResultType )) {
            spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                    "Invalid site result type: %s: %u", siteName, siteResultType );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }
        const char *siteResultState = spectre_marshal_data_get_str( siteData, "password", NULL );
        SpectreResultType siteLoginType = spectre_default_num( SpectreResultNone,
                spectre_marshal_data_get_num( siteData, "login_type", NULL ) );
        if (!spectre_type_short_name( siteLoginType )) {
            spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                    "Invalid site login type: %s: %u", siteName, siteLoginType );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }
        const char *siteLoginState = spectre_marshal_data_get_str( siteData, "login_name", NULL );
        unsigned int siteUses = spectre_default_num( 0U,
                spectre_marshal_data_get_num( siteData, "uses", NULL ) );
        str_lastUsed = spectre_marshal_data_get_str( siteData, "last_used", NULL );
        time_t siteLastUsed = spectre_get_timegm( str_lastUsed );
        if (!siteLastUsed) {
            spectre_marshal_error( file, SpectreMarshalErrorIllegal,
                    "Invalid site last used: %s: %s", siteName, str_lastUsed );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }

        const char *siteURL = spectre_marshal_data_get_str( siteData, "_ext_spectre", "url", NULL );

        SpectreMarshalledSite *site = spectre_marshal_site( user, siteName, siteResultType, siteCounter, algorithm );
        if (!site) {
            spectre_marshal_error( file, SpectreMarshalErrorInternal,
                    "Couldn't allocate a new site." );
            spectre_free( &userKey, sizeof( *userKey ) );
            spectre_marshal_free( &user );
            return NULL;
        }

        site->loginType = siteLoginType;
        site->url = siteURL? spectre_strdup( siteURL ): NULL;
        site->uses = siteUses;
        site->lastUsed = siteLastUsed;
        if (!user->redacted) {
            // Clear Text
            spectre_free( &userKey, sizeof( *userKey ) );
            if (!userKeyProvider || !(userKey = userKeyProvider( site->algorithm, user->userName ))) {
                spectre_marshal_error( file, SpectreMarshalErrorInternal,
                        "Couldn't derive user key." );
                spectre_free( &userKey, sizeof( *userKey ) );
                spectre_marshal_free( &user );
                return NULL;
            }

            if (siteResultState && strlen( siteResultState ) && userKey)
                site->resultState = spectre_site_state( userKey, site->siteName,
                        site->resultType, siteResultState, site->counter, SpectreKeyPurposeAuthentication, NULL );
            if (siteLoginState && strlen( siteLoginState ) && userKey)
                site->loginState = spectre_site_state( userKey, site->siteName,
                        site->loginType, siteLoginState, SpectreCounterInitial, SpectreKeyPurposeIdentification, NULL );
        }
        else {
            // Redacted
            if (siteResultState && strlen( siteResultState ))
                site->resultState = spectre_strdup( siteResultState );
            if (siteLoginState && strlen( siteLoginState ))
                site->loginState = spectre_strdup( siteLoginState );
        }

        const SpectreMarshalledData *questions = spectre_marshal_data_find( siteData, "questions", NULL );
        for (size_t q = 0; q < (questions? questions->children_count: 0); ++q) {
            const SpectreMarshalledData *questionData = &questions->children[q];
            SpectreMarshalledQuestion *question = spectre_marshal_question( site, questionData->obj_key );
            const char *answerState = spectre_marshal_data_get_str( questionData, "answer", NULL );
            question->type = spectre_default_num( SpectreResultTemplatePhrase,
                    spectre_marshal_data_get_num( questionData, "type", NULL ) );

            if (!user->redacted) {
                // Clear Text
                if (answerState && strlen( answerState ) && userKey)
                    question->state = spectre_site_state( userKey, site->siteName,
                            question->type, answerState, SpectreCounterInitial, SpectreKeyPurposeRecovery, question->keyword );
            }
            else {
                // Redacted
                if (answerState && strlen( answerState ))
                    question->state = spectre_strdup( answerState );
            }
        }
    }
    spectre_free( &userKey, sizeof( *userKey ) );

    return user;
}

const SpectreFormat spectre_format_named(
        const char *formatName) {

    if (!formatName || !strlen( formatName ))
        return SpectreFormatNone;

    if (spectre_strncasecmp( spectre_format_name( SpectreFormatNone ), formatName, strlen( formatName ) ) == OK)
        return SpectreFormatNone;
    if (spectre_strncasecmp( spectre_format_name( SpectreFormatFlat ), formatName, strlen( formatName ) ) == OK)
        return SpectreFormatFlat;
    if (spectre_strncasecmp( spectre_format_name( SpectreFormatJSON ), formatName, strlen( formatName ) ) == OK)
        return SpectreFormatJSON;

    wrn( "Not a format name: %s", formatName );
    return (SpectreFormat)ERR;
}

const char *spectre_format_name(
        const SpectreFormat format) {

    switch (format) {
        case SpectreFormatNone:
            return "none";
        case SpectreFormatFlat:
            return "flat";
        case SpectreFormatJSON:
            return "json";
        default: {
            wrn( "Unknown format: %d", format );
            return NULL;
        }
    }
}

const char *spectre_format_extension(
        const SpectreFormat format) {

    switch (format) {
        case SpectreFormatNone:
            return NULL;
        case SpectreFormatFlat:
            return "mpsites";
        case SpectreFormatJSON:
            return "mpjson";
        default: {
            wrn( "Unknown format: %d", format );
            return NULL;
        }
    }
}

const char **spectre_format_extensions(
        const SpectreFormat format, size_t *count) {

    *count = 0;
    switch (format) {
        case SpectreFormatNone:
            return NULL;
        case SpectreFormatFlat:
            return spectre_strings( count,
                    spectre_format_extension( format ), "mpsites.txt", "txt", NULL );
        case SpectreFormatJSON:
            return spectre_strings( count,
                    spectre_format_extension( format ), "mpsites.json", "json", NULL );
        default: {
            wrn( "Unknown format: %d", format );
            return NULL;
        }
    }
}
