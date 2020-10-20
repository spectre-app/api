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


#include "mpw-marshal.h"
#include "mpw-util.h"
#include "mpw-marshal-util.h"

MP_LIBS_BEGIN
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
MP_LIBS_END

static const MPMasterKey *__mpw_masterKeyProvider_currentKey = NULL;
static MPAlgorithmVersion __mpw_masterKeyProvider_currentAlgorithm = (MPAlgorithmVersion)-1;
static MPMasterKeyProviderProxy __mpw_masterKeyProvider_currentProxy = NULL;
static const char *__mpw_masterKeyProvider_currentPassword = NULL;

static bool __mpw_masterKeyProvider_str(const MPMasterKey **currentKey, MPAlgorithmVersion *currentAlgorithm,
        MPAlgorithmVersion algorithm, const char *fullName) {

    if (!currentKey)
        return mpw_free_string( &__mpw_masterKeyProvider_currentPassword );

    return mpw_update_master_key( currentKey, currentAlgorithm, algorithm, fullName, __mpw_masterKeyProvider_currentPassword );
}

static const MPMasterKey *__mpw_masterKeyProvider_proxy(MPAlgorithmVersion algorithm, const char *fullName) {

    if (!__mpw_masterKeyProvider_currentProxy)
        return NULL;
    if (!__mpw_masterKeyProvider_currentProxy(
            &__mpw_masterKeyProvider_currentKey, &__mpw_masterKeyProvider_currentAlgorithm, algorithm, fullName ))
        return NULL;

    return mpw_memdup( __mpw_masterKeyProvider_currentKey, sizeof( *__mpw_masterKeyProvider_currentKey ) );
}

MPMasterKeyProvider mpw_masterKeyProvider_str(const char *masterPassword) {

    mpw_masterKeyProvider_free();
    __mpw_masterKeyProvider_currentPassword = mpw_strdup( masterPassword );
    return mpw_masterKeyProvider_proxy( __mpw_masterKeyProvider_str );
}

MPMasterKeyProvider mpw_masterKeyProvider_proxy(const MPMasterKeyProviderProxy proxy) {

    mpw_masterKeyProvider_free();
    __mpw_masterKeyProvider_currentProxy = proxy;
    return __mpw_masterKeyProvider_proxy;
}

void mpw_masterKeyProvider_free() {

    mpw_free( &__mpw_masterKeyProvider_currentKey, sizeof( *__mpw_masterKeyProvider_currentKey ) );
    __mpw_masterKeyProvider_currentAlgorithm = (MPAlgorithmVersion)-1;
    if (__mpw_masterKeyProvider_currentProxy) {
        __mpw_masterKeyProvider_currentProxy( NULL, NULL, MPAlgorithmVersionCurrent, NULL );
        __mpw_masterKeyProvider_currentProxy = NULL;
    }
}

MPMarshalledUser *mpw_marshal_user(
        const char *fullName, MPMasterKeyProvider masterKeyProvider, const MPAlgorithmVersion algorithmVersion) {

    MPMarshalledUser *user;
    if (!fullName || !(user = malloc( sizeof( MPMarshalledUser ) )))
        return NULL;

    *user = (MPMarshalledUser){
            .masterKeyProvider = masterKeyProvider,
            .algorithm = algorithmVersion,
            .redacted = true,

            .avatar = 0,
            .fullName = mpw_strdup( fullName ),
            .identicon = MPIdenticonUnset,
            .keyID = MPNoKeyID,
            .defaultType = MPResultTypeDefaultResult,
            .loginType = MPResultTypeDefaultLogin,
            .loginState = NULL,
            .lastUsed = 0,

            .services_count = 0,
            .services = NULL,
    };
    return user;
}

MPMarshalledService *mpw_marshal_service(
        MPMarshalledUser *user, const char *serviceName, const MPResultType resultType,
        const MPCounterValue keyCounter, const MPAlgorithmVersion algorithmVersion) {

    if (!serviceName)
        return NULL;
    if (!mpw_realloc( &user->services, NULL, MPMarshalledService, ++user->services_count )) {
        user->services_count--;
        return NULL;
    }

    MPMarshalledService *service = &user->services[user->services_count - 1];
    *service = (MPMarshalledService){
            .serviceName = mpw_strdup( serviceName ),
            .algorithm = algorithmVersion,
            .counter = keyCounter,

            .resultType = resultType,
            .resultState = NULL,

            .loginType = MPResultTypeNone,
            .loginState = NULL,

            .url = NULL,
            .uses = 0,
            .lastUsed = 0,

            .questions_count = 0,
            .questions = NULL,
    };
    return service;
}

MPMarshalledQuestion *mpw_marshal_question(
        MPMarshalledService *service, const char *keyword) {

    if (!mpw_realloc( &service->questions, NULL, MPMarshalledQuestion, ++service->questions_count )) {
        service->questions_count--;
        return NULL;
    }
    if (!keyword)
        keyword = "";

    MPMarshalledQuestion *question = &service->questions[service->questions_count - 1];
    *question = (MPMarshalledQuestion){
            .keyword = mpw_strdup( keyword ),
            .type = MPResultTypeTemplatePhrase,
            .state = NULL,
    };
    return question;
}

MPMarshalledFile *mpw_marshal_file(
        MPMarshalledFile *file, MPMarshalledInfo *info, MPMarshalledData *data) {

    if (!file) {
        if (!(file = malloc( sizeof( MPMarshalledFile ) )))
            return NULL;

        *file = (MPMarshalledFile){ .info = NULL, .data = NULL, .error = (MPMarshalError){ .type = MPMarshalSuccess, .message = NULL } };
    }

    if (data && data != file->data) {
        mpw_marshal_data_free( &file->data );
        file->data = data;
    }
    if (info && info != file->info) {
        mpw_marshal_info_free( &file->info );
        file->info = info;
    }

    return file;
}

MPMarshalledFile *mpw_marshal_error(
        MPMarshalledFile *file, MPMarshalErrorType type, const char *format, ...) {

    file = mpw_marshal_file( file, NULL, NULL );
    if (!file)
        return NULL;

    va_list args;
    va_start( args, format );
    file->error = (MPMarshalError){ type, mpw_vstr( format, args ) };
    va_end( args );

    return file;
}

void mpw_marshal_info_free(
        MPMarshalledInfo **info) {

    if (!info || !*info)
        return;

    mpw_free_strings( &(*info)->fullName, NULL );
    mpw_free( info, sizeof( MPMarshalledInfo ) );
}

void mpw_marshal_user_free(
        MPMarshalledUser **user) {

    if (!user || !*user)
        return;

    mpw_free_strings( &(*user)->fullName, NULL );

    for (size_t s = 0; s < (*user)->services_count; ++s) {
        MPMarshalledService *service = &(*user)->services[s];
        mpw_free_strings( &service->serviceName, &service->resultState, &service->loginState, &service->url, NULL );

        for (size_t q = 0; q < service->questions_count; ++q) {
            MPMarshalledQuestion *question = &service->questions[q];
            mpw_free_strings( &question->keyword, &question->state, NULL );
        }
        mpw_free( &service->questions, sizeof( MPMarshalledQuestion ) * service->questions_count );
    }

    mpw_free( &(*user)->services, sizeof( MPMarshalledService ) * (*user)->services_count );
    mpw_free( user, sizeof( MPMarshalledUser ) );
}

void mpw_marshal_data_free(
        MPMarshalledData **data) {

    if (!data || !*data)
        return;

    mpw_marshal_data_set_null( *data, NULL );
    mpw_free_string( &(*data)->obj_key );
    mpw_free( data, sizeof( MPMarshalledData ) );
}

void mpw_marshal_file_free(
        MPMarshalledFile **file) {

    if (!file || !*file)
        return;

    mpw_marshal_info_free( &(*file)->info );
    mpw_marshal_data_free( &(*file)->data );
    mpw_free_string( &(*file)->error.message );
    mpw_free( file, sizeof( MPMarshalledFile ) );
}

MPMarshalledData *mpw_marshal_data_new() {

    MPMarshalledData *data = malloc( sizeof( MPMarshalledData ) );
    *data = (MPMarshalledData){};
    mpw_marshal_data_set_null( data, NULL );
    data->is_null = false;
    return data;
}

MPMarshalledData *mpw_marshal_data_vget(
        MPMarshalledData *data, va_list nodes) {

    MPMarshalledData *parent = data, *child = parent;
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
            if (!mpw_realloc( &parent->children, NULL, MPMarshalledData, ++parent->children_count )) {
                --parent->children_count;
                break;
            }
            *(child = &parent->children[parent->children_count - 1]) = (MPMarshalledData){ .obj_key = mpw_strdup( node ) };
            mpw_marshal_data_set_null( child, NULL );
            child->is_null = false;
        }
    }

    return child;
}

MPMarshalledData *mpw_marshal_data_get(
        MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    MPMarshalledData *child = mpw_marshal_data_vget( data, nodes );
    va_end( nodes );

    return child;
}

const MPMarshalledData *mpw_marshal_data_vfind(
        const MPMarshalledData *data, va_list nodes) {

    const MPMarshalledData *parent = data, *child = parent;
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

const MPMarshalledData *mpw_marshal_data_find(
        const MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    const MPMarshalledData *child = mpw_marshal_data_vfind( data, nodes );
    va_end( nodes );

    return child;
}

bool mpw_marshal_data_vis_null(
        const MPMarshalledData *data, va_list nodes) {

    const MPMarshalledData *child = mpw_marshal_data_vfind( data, nodes );
    return !child || child->is_null;
}

bool mpw_marshal_data_is_null(
        const MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool value = mpw_marshal_data_vis_null( data, nodes );
    va_end( nodes );

    return value;
}

bool mpw_marshal_data_vset_null(
        MPMarshalledData *data, va_list nodes) {

    MPMarshalledData *child = mpw_marshal_data_vget( data, nodes );
    if (!child)
        return false;

    mpw_free_string( &child->str_value );
    for (unsigned int c = 0; c < child->children_count; ++c) {
        mpw_marshal_data_set_null( &child->children[c], NULL );
        mpw_free_string( &child->children[c].obj_key );
    }
    mpw_free( &child->children, sizeof( MPMarshalledData ) * child->children_count );
    child->children_count = 0;
    child->num_value = NAN;
    child->is_bool = false;
    child->is_null = true;
    return true;
}

bool mpw_marshal_data_set_null(
        MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = mpw_marshal_data_vset_null( data, nodes );
    va_end( nodes );

    return success;
}

bool mpw_marshal_data_vget_bool(
        const MPMarshalledData *data, va_list nodes) {

    const MPMarshalledData *child = mpw_marshal_data_vfind( data, nodes );
    return child && child->is_bool && child->num_value != false;
}

bool mpw_marshal_data_get_bool(
        const MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool value = mpw_marshal_data_vget_bool( data, nodes );
    va_end( nodes );

    return value;
}

bool mpw_marshal_data_vset_bool(
        const bool value, MPMarshalledData *data, va_list nodes) {

    MPMarshalledData *child = mpw_marshal_data_vget( data, nodes );
    if (!child || !mpw_marshal_data_set_null( child, NULL ))
        return false;

    child->is_null = false;
    child->is_bool = true;
    child->num_value = value != false;
    return true;
}

bool mpw_marshal_data_set_bool(
        const bool value, MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = mpw_marshal_data_vset_bool( value, data, nodes );
    va_end( nodes );

    return success;
}

double mpw_marshal_data_vget_num(
        const MPMarshalledData *data, va_list nodes) {

    const MPMarshalledData *child = mpw_marshal_data_vfind( data, nodes );
    return child == NULL? NAN: child->num_value;
}

double mpw_marshal_data_get_num(
        const MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    double value = mpw_marshal_data_vget_num( data, nodes );
    va_end( nodes );

    return value;
}

bool mpw_marshal_data_vset_num(
        const double value, MPMarshalledData *data, va_list nodes) {

    MPMarshalledData *child = mpw_marshal_data_vget( data, nodes );
    if (!child || !mpw_marshal_data_set_null( child, NULL ))
        return false;

    child->is_null = false;
    child->num_value = value;
    child->str_value = mpw_str( "%g", value );
    return true;
}

bool mpw_marshal_data_set_num(
        const double value, MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = mpw_marshal_data_vset_num( value, data, nodes );
    va_end( nodes );

    return success;
}

const char *mpw_marshal_data_vget_str(
        const MPMarshalledData *data, va_list nodes) {

    const MPMarshalledData *child = mpw_marshal_data_vfind( data, nodes );
    return child == NULL? NULL: child->str_value;
}

const char *mpw_marshal_data_get_str(
        const MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    const char *value = mpw_marshal_data_vget_str( data, nodes );
    va_end( nodes );

    return value;
}

bool mpw_marshal_data_vset_str(
        const char *value, MPMarshalledData *data, va_list nodes) {

    MPMarshalledData *child = mpw_marshal_data_vget( data, nodes );
    if (!child || !mpw_marshal_data_set_null( child, NULL ))
        return false;

    if (value) {
        child->is_null = false;
        child->str_value = mpw_strdup( value );
    }

    return true;
}

bool mpw_marshal_data_set_str(
        const char *value, MPMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = mpw_marshal_data_vset_str( value, data, nodes );
    va_end( nodes );

    return success;
}

void mpw_marshal_data_keep(
        MPMarshalledData *data, bool (*filter)(MPMarshalledData *, void *), void *args) {

    size_t children_count = 0;
    MPMarshalledData *children = NULL;

    for (size_t c = 0; c < data->children_count; ++c) {
        MPMarshalledData *child = &data->children[c];
        if (filter( child, args )) {
            // Valid child in this object, keep it.
            ++children_count;

            if (children) {
                if (!mpw_realloc( &children, NULL, MPMarshalledData, children_count )) {
                    --children_count;
                    continue;
                }
                child->arr_index = children_count - 1;
                children[child->arr_index] = *child;
            }
        }
        else {
            // Not a valid child in this object, remove it.
            mpw_marshal_data_set_null( child, NULL );
            mpw_free_string( &child->obj_key );

            if (!children)
                children = mpw_memdup( data->children, sizeof( MPMarshalledData ) * children_count );
        }
    }

    if (children) {
        mpw_free( &data->children, sizeof( MPMarshalledData ) * data->children_count );
        data->children = children;
        data->children_count = children_count;
    }
}

bool mpw_marshal_data_keep_none(
        MPMarshalledData *child, void *args) {

    return false;
}

static const char *mpw_marshal_write_flat(
        MPMarshalledFile *file) {

    const MPMarshalledData *data = file->data;
    if (!data) {
        mpw_marshal_error( file, MPMarshalErrorMissing, "Missing data." );
        return NULL;
    }

    char *out = NULL;
    mpw_string_pushf( &out, "# Master Password service export\n" );
    mpw_string_pushf( &out, mpw_marshal_data_get_bool( data, "export", "redacted", NULL )?
                            "#     Export of service names and stored passwords (unless device-private) encrypted with the master key.\n":
                            "#     Export of service names and passwords in clear-text.\n" );
    mpw_string_pushf( &out, "# \n" );
    mpw_string_pushf( &out, "##\n" );
    mpw_string_pushf( &out, "# Format: %d\n", 1 );

    mpw_string_pushf( &out, "# Date: %s\n", mpw_default( "", mpw_marshal_data_get_str( data, "export", "date", NULL ) ) );
    mpw_string_pushf( &out, "# User Name: %s\n", mpw_default( "", mpw_marshal_data_get_str( data, "user", "full_name", NULL ) ) );
    mpw_string_pushf( &out, "# Full Name: %s\n", mpw_default( "", mpw_marshal_data_get_str( data, "user", "full_name", NULL ) ) );
    mpw_string_pushf( &out, "# Avatar: %u\n", (unsigned int)mpw_marshal_data_get_num( data, "user", "avatar", NULL ) );
    mpw_string_pushf( &out, "# Identicon: %s\n", mpw_default( "", mpw_marshal_data_get_str( data, "user", "identicon", NULL ) ) );
    mpw_string_pushf( &out, "# Key ID: %s\n", mpw_default( "", mpw_marshal_data_get_str( data, "user", "key_id", NULL ) ) );
    mpw_string_pushf( &out, "# Algorithm: %d\n", (MPAlgorithmVersion)mpw_marshal_data_get_num( data, "user", "algorithm", NULL ) );
    mpw_string_pushf( &out, "# Default Type: %d\n", (MPResultType)mpw_marshal_data_get_num( data, "user", "default_type", NULL ) );
    mpw_string_pushf( &out, "# Passwords: %s\n", mpw_marshal_data_get_bool( data, "export", "redacted", NULL )? "PROTECTED": "VISIBLE" );
    mpw_string_pushf( &out, "##\n" );
    mpw_string_pushf( &out, "#\n" );
    mpw_string_pushf( &out, "#               Last     Times  Password                      Login\t                  Service\tService\n" );
    mpw_string_pushf( &out, "#               used      used      type                       name\t                     name\tpassword\n" );

    // Services.
    const char *typeString;
    const MPMarshalledData *services = mpw_marshal_data_find( data, "services", NULL );
    for (size_t s = 0; s < (services? services->children_count: 0); ++s) {
        const MPMarshalledData *service = &services->children[s];
        mpw_string_pushf( &out, "%s  %8ld  %8s  %25s\t%25s\t%s\n",
                mpw_default( "", mpw_marshal_data_get_str( service, "last_used", NULL ) ),
                (long)mpw_marshal_data_get_num( service, "uses", NULL ),
                typeString = mpw_str( "%lu:%lu:%lu",
                        (long)mpw_marshal_data_get_num( service, "type", NULL ),
                        (long)mpw_marshal_data_get_num( service, "algorithm", NULL ),
                        (long)mpw_marshal_data_get_num( service, "counter", NULL ) ),
                mpw_default( "", mpw_marshal_data_get_str( service, "login_name", NULL ) ),
                service->obj_key,
                mpw_default( "", mpw_marshal_data_get_str( service, "password", NULL ) ) );
        mpw_free_string( &typeString );
    }

    if (!out)
        mpw_marshal_error( file, MPMarshalErrorFormat, "Couldn't encode JSON." );
    else
        mpw_marshal_error( file, MPMarshalSuccess, NULL );

    return out;
}

#if MPW_JSON

static json_object *mpw_get_json_data(
        const MPMarshalledData *data) {

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
        MPMarshalledData *child = &data->children[c];
        if (!obj) {
            if (child->obj_key)
                obj = json_object_new_object();
            else
                obj = json_object_new_array();
        }

        json_object *child_obj = mpw_get_json_data( child );
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

static const char *mpw_marshal_write_json(
        MPMarshalledFile *file) {

    json_object *json_file = mpw_get_json_data( file->data );
    if (!json_file) {
        mpw_marshal_error( file, MPMarshalErrorFormat, "Couldn't serialize export data." );
        return NULL;
    }

    json_object *json_export = mpw_get_json_object( json_file, "export", true );
    json_object_object_add( json_export, "format", json_object_new_int( 2 ) );

    const char *out = mpw_strdup( json_object_to_json_string_ext( json_file,
            JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_NOSLASHESCAPE ) );
    json_object_put( json_file );

    if (!out)
        mpw_marshal_error( file, MPMarshalErrorFormat, "Couldn't encode JSON." );
    else
        mpw_marshal_error( file, MPMarshalSuccess, NULL );

    return out;
}

#endif

static bool mpw_marshal_data_keep_service_exists(
        MPMarshalledData *child, void *args) {

    MPMarshalledUser *user = args;

    for (size_t s = 0; s < user->services_count; ++s) {
        if (strcmp( (&user->services[s])->serviceName, child->obj_key ) == OK)
            return true;
    }

    return false;
}

static bool mpw_marshal_data_keep_question_exists(
        MPMarshalledData *child, void *args) {

    MPMarshalledService *service = args;

    for (size_t s = 0; s < service->questions_count; ++s) {
        if (strcmp( (&service->questions[s])->keyword, child->obj_key ) == OK)
            return true;
    }

    return false;
}

const char *mpw_marshal_write(
        const MPMarshalFormat outFormat, MPMarshalledFile **file_, MPMarshalledUser *user) {

    MPMarshalledFile *file = file_? *file_: NULL;
    file = mpw_marshal_file( file, NULL, file && file->data? file->data: mpw_marshal_data_new() );
    if (file_)
        *file_ = file;
    if (!file)
        return NULL;
    if (!file->data) {
        if (!file_)
            mpw_marshal_file_free( &file );
        else
            mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't allocate data." );
        return NULL;
    }
    mpw_marshal_error( file, MPMarshalSuccess, NULL );

    if (user) {
        if (!user->fullName || !strlen( user->fullName )) {
            if (!file_)
                mpw_marshal_file_free( &file );
            else
                mpw_marshal_error( file, MPMarshalErrorMissing, "Missing full name." );
            return NULL;
        }

        const MPMasterKey *masterKey = NULL;
        if (user->masterKeyProvider)
            masterKey = user->masterKeyProvider( user->algorithm, user->fullName );

        // Section: "export"
        MPMarshalledData *data_export = mpw_marshal_data_get( file->data, "export", NULL );
        char dateString[21];
        time_t now = time( NULL );
        if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &now ) ))
            mpw_marshal_data_set_str( dateString, data_export, "date", NULL );
        mpw_marshal_data_set_bool( user->redacted, data_export, "redacted", NULL );

        // Section: "user"
        const char *loginState = NULL;
        if (!user->redacted) {
            // Clear Text
            mpw_free( &masterKey, sizeof( *masterKey ) );
            if (!user->masterKeyProvider || !(masterKey = user->masterKeyProvider( user->algorithm, user->fullName ))) {
                if (!file_)
                    mpw_marshal_file_free( &file );
                else
                    mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't derive master key." );
                return NULL;
            }

            loginState = mpw_service_result( masterKey, user->fullName,
                    user->loginType, user->loginState, MPCounterValueInitial, MPKeyPurposeIdentification, NULL );
        }
        else {
            // Redacted
            if (user->loginType & MPServiceFeatureExportContent && user->loginState && strlen( user->loginState ))
                loginState = mpw_strdup( user->loginState );
        }

        const char *identiconString;
        MPMarshalledData *data_user = mpw_marshal_data_get( file->data, "user", NULL );
        mpw_marshal_data_set_num( user->avatar, data_user, "avatar", NULL );
        mpw_marshal_data_set_str( user->fullName, data_user, "full_name", NULL );
        mpw_marshal_data_set_str( identiconString = mpw_identicon_encode( user->identicon ), data_user, "identicon", NULL );
        mpw_marshal_data_set_num( user->algorithm, data_user, "algorithm", NULL );
        mpw_marshal_data_set_str( user->keyID.hex, data_user, "key_id", NULL );
        mpw_marshal_data_set_num( user->defaultType, data_user, "default_type", NULL );
        mpw_marshal_data_set_num( user->loginType, data_user, "login_type", NULL );
        mpw_marshal_data_set_str( loginState, data_user, "login_name", NULL );
        if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &user->lastUsed ) ))
            mpw_marshal_data_set_str( dateString, data_user, "last_used", NULL );
        mpw_free_strings( &identiconString, &loginState, NULL );

        // Section "services"
        MPMarshalledData *data_services = mpw_marshal_data_get( file->data, "services", NULL );
        mpw_marshal_data_keep( data_services, mpw_marshal_data_keep_service_exists, user );
        for (size_t s = 0; s < user->services_count; ++s) {
            MPMarshalledService *service = &user->services[s];
            if (!service->serviceName || !strlen( service->serviceName ))
                continue;

            const char *resultState = NULL;
            if (!user->redacted) {
                // Clear Text
                mpw_free( &masterKey, sizeof( *masterKey ) );
                if (!user->masterKeyProvider || !(masterKey = user->masterKeyProvider( service->algorithm, user->fullName ))) {
                    if (!file_)
                        mpw_marshal_file_free( &file );
                    else
                        mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't derive master key." );
                    return NULL;
                }

                resultState = mpw_service_result( masterKey, service->serviceName,
                        service->resultType, service->resultState, service->counter, MPKeyPurposeAuthentication, NULL );
                loginState = mpw_service_result( masterKey, service->serviceName,
                        service->loginType, service->loginState, MPCounterValueInitial, MPKeyPurposeIdentification, NULL );
            }
            else {
                // Redacted
                if (service->resultType & MPServiceFeatureExportContent && service->resultState && strlen( service->resultState ))
                    resultState = mpw_strdup( service->resultState );
                if (service->loginType & MPServiceFeatureExportContent && service->loginState && strlen( service->loginState ))
                    loginState = mpw_strdup( service->loginState );
            }

            mpw_marshal_data_set_num( service->counter, data_services, service->serviceName, "counter", NULL );
            mpw_marshal_data_set_num( service->algorithm, data_services, service->serviceName, "algorithm", NULL );
            mpw_marshal_data_set_num( service->resultType, data_services, service->serviceName, "type", NULL );
            mpw_marshal_data_set_str( resultState, data_services, service->serviceName, "password", NULL );
            mpw_marshal_data_set_num( service->loginType, data_services, service->serviceName, "login_type", NULL );
            mpw_marshal_data_set_str( loginState, data_services, service->serviceName, "login_name", NULL );
            mpw_marshal_data_set_num( service->uses, data_services, service->serviceName, "uses", NULL );
            if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &service->lastUsed ) ))
                mpw_marshal_data_set_str( dateString, data_services, service->serviceName, "last_used", NULL );

            MPMarshalledData *data_questions = mpw_marshal_data_get( file->data, "services", service->serviceName, "questions", NULL );
            mpw_marshal_data_keep( data_questions, mpw_marshal_data_keep_question_exists, service );
            for (size_t q = 0; q < service->questions_count; ++q) {
                MPMarshalledQuestion *question = &service->questions[q];
                if (!question->keyword)
                    continue;

                const char *answer = NULL;
                if (!user->redacted) {
                    // Clear Text
                    answer = mpw_service_result( masterKey, service->serviceName,
                            question->type, question->state, MPCounterValueInitial, MPKeyPurposeRecovery, question->keyword );
                }
                else {
                    // Redacted
                    if (question->state && strlen( question->state ) && service->resultType & MPServiceFeatureExportContent)
                        answer = mpw_strdup( question->state );
                }

                mpw_marshal_data_set_num( question->type, data_questions, question->keyword, "type", NULL );
                mpw_marshal_data_set_str( answer, data_questions, question->keyword, "answer", NULL );
                mpw_free_strings( &answer, NULL );
            }

            mpw_marshal_data_set_str( service->url, data_services, service->serviceName, "_ext_mpw", "url", NULL );
            mpw_free_strings( &resultState, &loginState, NULL );
        }
    }

    const char *out = NULL;
    switch (outFormat) {
        case MPMarshalFormatNone:
            mpw_marshal_error( file, MPMarshalSuccess, NULL );
            break;
        case MPMarshalFormatFlat:
            out = mpw_marshal_write_flat( file );
            break;
#if MPW_JSON
        case MPMarshalFormatJSON:
            out = mpw_marshal_write_json( file );
            break;
#endif
        default:
            mpw_marshal_error( file, MPMarshalErrorFormat, "Unsupported output format: %u", outFormat );
            break;
    }
    if (out && file->error.type == MPMarshalSuccess)
        file = mpw_marshal_read( file, out );
    if (file_)
        *file_ = file;
    else
        mpw_marshal_file_free( &file );

    return out;
}

static void mpw_marshal_read_flat(
        MPMarshalledFile *file, const char *in) {

    if (!file)
        return;

    mpw_marshal_file( file, NULL, mpw_marshal_data_new() );
    if (!file->data) {
        mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't allocate data." );
        return;
    }

    // Parse import data.
    unsigned int format = 0, avatar = 0;
    const char *fullName = NULL, *keyID = NULL, *identiconString = NULL;
    MPAlgorithmVersion algorithm = MPAlgorithmVersionCurrent;
    MPIdenticon identicon = MPIdenticonUnset;
    MPResultType defaultType = MPResultTypeDefaultResult;
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
                if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &exportDate ) )) {
                    mpw_marshal_data_set_str( dateString, file->data, "export", "date", NULL );
                    mpw_marshal_data_set_str( dateString, file->data, "user", "last_used", NULL );
                }
                mpw_marshal_data_set_num( algorithm, file->data, "user", "algorithm", NULL );
                mpw_marshal_data_set_bool( importRedacted, file->data, "export", "redacted", NULL );
                mpw_marshal_data_set_num( avatar, file->data, "user", "avatar", NULL );
                mpw_marshal_data_set_str( fullName, file->data, "user", "full_name", NULL );
                mpw_marshal_data_set_str( identiconString = mpw_identicon_encode( identicon ), file->data, "user", "identicon", NULL );
                mpw_marshal_data_set_str( keyID, file->data, "user", "key_id", NULL );
                mpw_marshal_data_set_num( defaultType, file->data, "user", "default_type", NULL );
                mpw_free_string( &identiconString );
                continue;
            }

            // Header
            const char *line = positionInLine;
            const char *headerName = mpw_get_token( &positionInLine, endOfLine, ":\n" );
            const char *headerValue = mpw_get_token( &positionInLine, endOfLine, "\n" );
            if (!headerName || !headerValue) {
                mpw_marshal_error( file, MPMarshalErrorStructure, "Invalid header: %s", mpw_strndup( line, (size_t)(endOfLine - line) ) );
                mpw_free_strings( &headerName, &headerValue, NULL );
                continue;
            }

            if (mpw_strcasecmp( headerName, "Format" ) == OK)
                format = (unsigned int)strtoul( headerValue, NULL, 10 );
            if (mpw_strcasecmp( headerName, "Date" ) == OK)
                exportDate = mpw_timegm( headerValue );
            if (mpw_strcasecmp( headerName, "Passwords" ) == OK)
                importRedacted = mpw_strcasecmp( headerValue, "VISIBLE" ) != OK;
            if (mpw_strcasecmp( headerName, "Algorithm" ) == OK) {
                unsigned long value = strtoul( headerValue, NULL, 10 );
                if (value < MPAlgorithmVersionFirst || value > MPAlgorithmVersionLast)
                    mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid user algorithm version: %s", headerValue );
                else
                    algorithm = (MPAlgorithmVersion)value;
            }
            if (mpw_strcasecmp( headerName, "Avatar" ) == OK)
                avatar = (unsigned int)strtoul( headerValue, NULL, 10 );
            if (mpw_strcasecmp( headerName, "Full Name" ) == OK || mpw_strcasecmp( headerName, "User Name" ) == OK)
                fullName = mpw_strdup( headerValue );
            if (mpw_strcasecmp( headerName, "Identicon" ) == OK)
                identicon = mpw_identicon_encoded( headerValue );
            if (mpw_strcasecmp( headerName, "Key ID" ) == OK)
                keyID = mpw_strdup( headerValue );
            if (mpw_strcasecmp( headerName, "Default Type" ) == OK) {
                unsigned long value = strtoul( headerValue, NULL, 10 );
                if (!mpw_type_short_name( (MPResultType)value ))
                    mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid user default type: %s", headerValue );
                else
                    defaultType = (MPResultType)value;
            }

            mpw_free_strings( &headerName, &headerValue, NULL );
            continue;
        }
        if (!headerEnded)
            continue;
        if (!fullName)
            mpw_marshal_error( file, MPMarshalErrorMissing, "Missing header: Full Name" );
        if (positionInLine >= endOfLine)
            continue;

        // Service
        const char *serviceName = NULL, *serviceResultState = NULL, *serviceLoginState = NULL;
        const char *str_lastUsed = NULL, *str_uses = NULL, *str_type = NULL, *str_algorithm = NULL, *str_counter = NULL;
        switch (format) {
            case 0: {
                str_lastUsed = mpw_get_token( &positionInLine, endOfLine, " \t\n" );
                str_uses = mpw_get_token( &positionInLine, endOfLine, " \t\n" );
                char *typeAndVersion = (char *)mpw_get_token( &positionInLine, endOfLine, " \t\n" );
                if (typeAndVersion) {
                    str_type = mpw_strdup( strtok( typeAndVersion, ":" ) );
                    str_algorithm = mpw_strdup( strtok( NULL, "" ) );
                    mpw_free_string( &typeAndVersion );
                }
                str_counter = mpw_str( "%u", MPCounterValueDefault );
                serviceLoginState = NULL;
                serviceName = mpw_get_token( &positionInLine, endOfLine, "\t\n" );
                serviceResultState = mpw_get_token( &positionInLine, endOfLine, "\n" );
                break;
            }
            case 1: {
                str_lastUsed = mpw_get_token( &positionInLine, endOfLine, " \t\n" );
                str_uses = mpw_get_token( &positionInLine, endOfLine, " \t\n" );
                char *typeAndVersionAndCounter = (char *)mpw_get_token( &positionInLine, endOfLine, " \t\n" );
                if (typeAndVersionAndCounter) {
                    str_type = mpw_strdup( strtok( typeAndVersionAndCounter, ":" ) );
                    str_algorithm = mpw_strdup( strtok( NULL, ":" ) );
                    str_counter = mpw_strdup( strtok( NULL, "" ) );
                    mpw_free_string( &typeAndVersionAndCounter );
                }
                serviceLoginState = mpw_get_token( &positionInLine, endOfLine, "\t\n" );
                serviceName = mpw_get_token( &positionInLine, endOfLine, "\t\n" );
                serviceResultState = mpw_get_token( &positionInLine, endOfLine, "\n" );
                break;
            }
            default: {
                mpw_marshal_error( file, MPMarshalErrorFormat, "Unexpected import format: %u", format );
                continue;
            }
        }

        if (serviceName && str_type && str_counter && str_algorithm && str_uses && str_lastUsed) {
            MPResultType serviceResultType = (MPResultType)strtoul( str_type, NULL, 10 );
            if (!mpw_type_short_name( serviceResultType )) {
                mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service type: %s: %s", serviceName, str_type );
                continue;
            }
            long long int value = strtoll( str_counter, NULL, 10 );
            if (value < MPCounterValueFirst || value > MPCounterValueLast) {
                mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service counter: %s: %s", serviceName, str_counter );
                continue;
            }
            MPCounterValue serviceKeyCounter = (MPCounterValue)value;
            value = strtoll( str_algorithm, NULL, 0 );
            if (value < MPAlgorithmVersionFirst || value > MPAlgorithmVersionLast) {
                mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service algorithm: %s: %s", serviceName, str_algorithm );
                continue;
            }
            MPAlgorithmVersion serviceAlgorithm = (MPAlgorithmVersion)value;
            time_t serviceLastUsed = mpw_timegm( str_lastUsed );
            if (!serviceLastUsed) {
                mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service last used: %s: %s", serviceName, str_lastUsed );
                continue;
            }
            MPResultType serviceLoginType = serviceLoginState && *serviceLoginState? MPResultTypeStatefulPersonal: MPResultTypeNone;

            char dateString[21];
            mpw_marshal_data_set_num( serviceAlgorithm, file->data, "services", serviceName, "algorithm", NULL );
            mpw_marshal_data_set_num( serviceKeyCounter, file->data, "services", serviceName, "counter", NULL );
            mpw_marshal_data_set_num( serviceResultType, file->data, "services", serviceName, "type", NULL );
            mpw_marshal_data_set_str( serviceResultState, file->data, "services", serviceName, "password", NULL );
            mpw_marshal_data_set_num( serviceLoginType, file->data, "services", serviceName, "login_type", NULL );
            mpw_marshal_data_set_str( serviceLoginState, file->data, "services", serviceName, "login_name", NULL );
            mpw_marshal_data_set_num( strtol( str_uses, NULL, 10 ), file->data, "services", serviceName, "uses", NULL );
            if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &serviceLastUsed ) ))
                mpw_marshal_data_set_str( dateString, file->data, "services", serviceName, "last_used", NULL );
        }
        else {
            mpw_marshal_error( file, MPMarshalErrorMissing,
                    "Missing one of: lastUsed=%s, uses=%s, type=%s, version=%s, counter=%s, loginName=%s, serviceName=%s",
                    str_lastUsed, str_uses, str_type, str_algorithm, str_counter, serviceLoginState, serviceName );
            continue;
        }

        mpw_free_strings( &str_lastUsed, &str_uses, &str_type, &str_algorithm, &str_counter, NULL );
        mpw_free_strings( &serviceLoginState, &serviceName, &serviceResultState, NULL );
    }
    mpw_free_strings( &fullName, &keyID, NULL );
}

#if MPW_JSON

static void mpw_marshal_read_json(
        MPMarshalledFile *file, const char *in) {

    if (!file)
        return;

    mpw_marshal_file( file, NULL, mpw_marshal_data_new() );
    if (!file->data) {
        mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't allocate data." );
        return;
    }

    // Parse import data.
    enum json_tokener_error json_error = json_tokener_success;
    json_object *json_file = json_tokener_parse_verbose( in, &json_error );
    if (!json_file || json_error != json_tokener_success) {
        mpw_marshal_error( file, MPMarshalErrorFormat, "Couldn't parse JSON: %s", json_tokener_error_desc( json_error ) );
        return;
    }

    mpw_set_json_data( file->data, json_file );
    json_object_put( json_file );

    // version 1 fixes:
    if (mpw_marshal_data_get_num( file->data, "export", "format", NULL ) == 1) {
        // - "sites" key renamed to "services".
        MPMarshalledData *services = (MPMarshalledData *)mpw_marshal_data_find( file->data, "services", NULL );
        if (!services) {
            services = (MPMarshalledData *)mpw_marshal_data_find( file->data, "sites", NULL );
            if (services) {
                mpw_free_string( &services->obj_key );
                services->obj_key = mpw_strdup( "services" );
            }
        }

        // - default login_type "name" written to file, preventing adoption of user-level standard login_type.
        for (size_t s = 0; s < (services? services->children_count: 0); ++s) {
            MPMarshalledData *service = &services->children[s];
            if (mpw_marshal_data_get_num( service, "login_type", NULL ) == MPResultTypeTemplateName)
                mpw_marshal_data_set_null( service, "login_type", NULL );
        }
    }

    return;
}

#endif

MPMarshalledFile *mpw_marshal_read(
        MPMarshalledFile *file, const char *in) {

    MPMarshalledInfo *info = malloc( sizeof( MPMarshalledInfo ) );
    file = mpw_marshal_file( file, info, NULL );
    if (!file)
        return NULL;

    mpw_marshal_error( file, MPMarshalSuccess, NULL );
    if (!info) {
        mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't allocate info." );
        return file;
    }

    *info = (MPMarshalledInfo){ .format = MPMarshalFormatNone, .identicon = MPIdenticonUnset };
    if (in && strlen( in )) {
        if (in[0] == '#') {
            info->format = MPMarshalFormatFlat;
            mpw_marshal_read_flat( file, in );
        }
        else if (in[0] == '{') {
            info->format = MPMarshalFormatJSON;
#if MPW_JSON
            mpw_marshal_read_json( file, in );
#else
            mpw_marshal_error( file, MPMarshalErrorFormat, "JSON support is not enabled." );
#endif
        }
    }

    // Section: "export"
    info->exportDate = mpw_timegm( mpw_strdup( mpw_marshal_data_get_str( file->data, "export", "date", NULL ) ) );
    info->redacted = mpw_marshal_data_get_bool( file->data, "export", "redacted", NULL )
                     || mpw_marshal_data_is_null( file->data, "export", "redacted", NULL );

    // Section: "user"
    info->algorithm = mpw_default_num( MPAlgorithmVersionCurrent, mpw_marshal_data_get_num( file->data, "user", "algorithm", NULL ) );
    info->avatar = mpw_default_num( 0U, mpw_marshal_data_get_num( file->data, "user", "avatar", NULL ) );
    info->fullName = mpw_strdup( mpw_marshal_data_get_str( file->data, "user", "full_name", NULL ) );
    info->identicon = mpw_identicon_encoded( mpw_marshal_data_get_str( file->data, "user", "identicon", NULL ) );
    info->keyID = mpw_id_str( mpw_marshal_data_get_str( file->data, "user", "key_id", NULL ) );
    info->lastUsed = mpw_timegm( mpw_marshal_data_get_str( file->data, "user", "last_used", NULL ) );

    return file;
}

MPMarshalledUser *mpw_marshal_auth(
        MPMarshalledFile *file, const MPMasterKeyProvider masterKeyProvider) {

    if (!file)
        return NULL;

    mpw_marshal_error( file, MPMarshalSuccess, NULL );
    if (!file->info) {
        mpw_marshal_error( file, MPMarshalErrorMissing, "File wasn't parsed yet." );
        return NULL;
    }
    if (!file->data) {
        mpw_marshal_error( file, MPMarshalErrorMissing, "No input data." );
        return NULL;
    }
    const MPMarshalledData *userData = mpw_marshal_data_find( file->data, "user", NULL );
    if (!userData) {
        mpw_marshal_error( file, MPMarshalErrorMissing, "Missing user data." );
        return NULL;
    }

    // Section: "user"
    bool fileRedacted = mpw_marshal_data_get_bool( file->data, "export", "redacted", NULL )
                        || mpw_marshal_data_is_null( file->data, "export", "redacted", NULL );
    MPAlgorithmVersion algorithm = mpw_default_num( MPAlgorithmVersionCurrent, mpw_marshal_data_get_num( userData, "algorithm", NULL ) );
    if (algorithm < MPAlgorithmVersionFirst || algorithm > MPAlgorithmVersionLast) {
        mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid user algorithm: %u", algorithm );
        return NULL;
    }
    unsigned int avatar = mpw_default_num( 0U, mpw_marshal_data_get_num( userData, "avatar", NULL ) );
    const char *fullName = mpw_marshal_data_get_str( userData, "full_name", NULL );
    if (!fullName || !strlen( fullName )) {
        mpw_marshal_error( file, MPMarshalErrorMissing, "Missing value for full name." );
        return NULL;
    }
    MPIdenticon identicon = mpw_identicon_encoded( mpw_marshal_data_get_str( userData, "identicon", NULL ) );
    MPKeyID keyID = mpw_id_str( mpw_marshal_data_get_str( userData, "key_id", NULL ) );
    MPResultType defaultType = mpw_default_num( MPResultTypeDefaultResult, mpw_marshal_data_get_num( userData, "default_type", NULL ) );
    if (!mpw_type_short_name( defaultType )) {
        mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid user default type: %u", defaultType );
        return NULL;
    }
    MPResultType loginType = mpw_default_num( MPResultTypeDefaultLogin, mpw_marshal_data_get_num( userData, "login_type", NULL ) );
    if (!mpw_type_short_name( loginType )) {
        mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid user login type: %u", loginType );
        return NULL;
    }
    const char *loginState = mpw_marshal_data_get_str( userData, "login_name", NULL );
    const char *str_lastUsed = mpw_marshal_data_get_str( userData, "last_used", NULL );
    time_t lastUsed = mpw_timegm( str_lastUsed );
    if (!lastUsed) {
        mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid user last used: %s", str_lastUsed );
        return NULL;
    }

    const MPMasterKey *masterKey = NULL;
    if (masterKeyProvider && !(masterKey = masterKeyProvider( algorithm, fullName ))) {
        mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't derive master key." );
        return NULL;
    }
    if (masterKey && !mpw_id_equals( &keyID, &masterKey->keyID )) {
        mpw_marshal_error( file, MPMarshalErrorMasterPassword, "Master key: %s, isn't user keyID: %s.", masterKey->keyID.hex, keyID.hex );
        mpw_free( &masterKey, sizeof( *masterKey ) );
        return NULL;
    }

    MPMarshalledUser *user = NULL;
    if (!(user = mpw_marshal_user( fullName, masterKeyProvider, algorithm ))) {
        mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't allocate a new user." );
        mpw_free( &masterKey, sizeof( *masterKey ) );
        mpw_marshal_user_free( &user );
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
        mpw_free( &masterKey, sizeof( *masterKey ) );
        if (!masterKeyProvider || !(masterKey = masterKeyProvider( user->algorithm, user->fullName ))) {
            mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't derive master key." );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }

        if (loginState && strlen( loginState ) && masterKey)
            user->loginState = mpw_service_state( masterKey, user->fullName, user->loginType, loginState, MPCounterValueInitial,
                    MPKeyPurposeIdentification, NULL );
    }
    else {
        // Redacted
        if (loginState && strlen( loginState ))
            user->loginState = mpw_strdup( loginState );
    }

    // Section "services"
    const MPMarshalledData *servicesData = mpw_marshal_data_find( file->data, "services", NULL );
    for (size_t s = 0; s < (servicesData? servicesData->children_count: 0); ++s) {
        const MPMarshalledData *serviceData = &servicesData->children[s];
        const char *serviceName = serviceData->obj_key;

        algorithm = mpw_default_num( user->algorithm, mpw_marshal_data_get_num( serviceData, "algorithm", NULL ) );
        if (algorithm < MPAlgorithmVersionFirst || algorithm > MPAlgorithmVersionLast) {
            mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service algorithm: %s: %u", serviceName, algorithm );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }
        MPCounterValue serviceCounter = mpw_default_num( MPCounterValueDefault, mpw_marshal_data_get_num( serviceData, "counter", NULL ) );
        if (serviceCounter < MPCounterValueFirst || serviceCounter > MPCounterValueLast) {
            mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service result counter: %s: %d", serviceName, serviceCounter );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }
        MPResultType serviceResultType = mpw_default_num( user->defaultType, mpw_marshal_data_get_num( serviceData, "type", NULL ) );
        if (!mpw_type_short_name( serviceResultType )) {
            mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service result type: %s: %u", serviceName, serviceResultType );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }
        const char *serviceResultState = mpw_marshal_data_get_str( serviceData, "password", NULL );
        MPResultType serviceLoginType = mpw_default_num( MPResultTypeNone, mpw_marshal_data_get_num( serviceData, "login_type", NULL ) );
        if (!mpw_type_short_name( serviceLoginType )) {
            mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service login type: %s: %u", serviceName, serviceLoginType );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }
        const char *serviceLoginState = mpw_marshal_data_get_str( serviceData, "login_name", NULL );
        unsigned int serviceUses = mpw_default_num( 0U, mpw_marshal_data_get_num( serviceData, "uses", NULL ) );
        str_lastUsed = mpw_marshal_data_get_str( serviceData, "last_used", NULL );
        time_t serviceLastUsed = mpw_timegm( str_lastUsed );
        if (!serviceLastUsed) {
            mpw_marshal_error( file, MPMarshalErrorIllegal, "Invalid service last used: %s: %s", serviceName, str_lastUsed );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }

        const char *serviceURL = mpw_marshal_data_get_str( serviceData, "_ext_mpw", "url", NULL );

        MPMarshalledService *service = mpw_marshal_service( user, serviceName, serviceResultType, serviceCounter, algorithm );
        if (!service) {
            mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't allocate a new service." );
            mpw_free( &masterKey, sizeof( *masterKey ) );
            mpw_marshal_user_free( &user );
            return NULL;
        }

        service->loginType = serviceLoginType;
        service->url = serviceURL? mpw_strdup( serviceURL ): NULL;
        service->uses = serviceUses;
        service->lastUsed = serviceLastUsed;
        if (!user->redacted) {
            // Clear Text
            mpw_free( &masterKey, sizeof( *masterKey ) );
            if (!masterKeyProvider || !(masterKey = masterKeyProvider( service->algorithm, user->fullName ))) {
                mpw_marshal_error( file, MPMarshalErrorInternal, "Couldn't derive master key." );
                mpw_free( &masterKey, sizeof( *masterKey ) );
                mpw_marshal_user_free( &user );
                return NULL;
            }

            if (serviceResultState && strlen( serviceResultState ) && masterKey)
                service->resultState = mpw_service_state( masterKey, service->serviceName,
                        service->resultType, serviceResultState, service->counter, MPKeyPurposeAuthentication, NULL );
            if (serviceLoginState && strlen( serviceLoginState ) && masterKey)
                service->loginState = mpw_service_state( masterKey, service->serviceName,
                        service->loginType, serviceLoginState, MPCounterValueInitial, MPKeyPurposeIdentification, NULL );
        }
        else {
            // Redacted
            if (serviceResultState && strlen( serviceResultState ))
                service->resultState = mpw_strdup( serviceResultState );
            if (serviceLoginState && strlen( serviceLoginState ))
                service->loginState = mpw_strdup( serviceLoginState );
        }

        const MPMarshalledData *questions = mpw_marshal_data_find( serviceData, "questions", NULL );
        for (size_t q = 0; q < (questions? questions->children_count: 0); ++q) {
            const MPMarshalledData *questionData = &questions->children[q];
            MPMarshalledQuestion *question = mpw_marshal_question( service, questionData->obj_key );
            const char *answerState = mpw_marshal_data_get_str( questionData, "answer", NULL );
            question->type = mpw_default_num( MPResultTypeTemplatePhrase, mpw_marshal_data_get_num( questionData, "type", NULL ) );

            if (!user->redacted) {
                // Clear Text
                if (answerState && strlen( answerState ) && masterKey)
                    question->state = mpw_service_state( masterKey, service->serviceName,
                            question->type, answerState, MPCounterValueInitial, MPKeyPurposeRecovery, question->keyword );
            }
            else {
                // Redacted
                if (answerState && strlen( answerState ))
                    question->state = mpw_strdup( answerState );
            }
        }
    }
    mpw_free( &masterKey, sizeof( *masterKey ) );

    return user;
}

const MPMarshalFormat mpw_format_named(
        const char *formatName) {

    if (!formatName || !strlen( formatName ))
        return MPMarshalFormatNone;

    if (mpw_strncasecmp( mpw_format_name( MPMarshalFormatNone ), formatName, strlen( formatName ) ) == OK)
        return MPMarshalFormatNone;
    if (mpw_strncasecmp( mpw_format_name( MPMarshalFormatFlat ), formatName, strlen( formatName ) ) == OK)
        return MPMarshalFormatFlat;
    if (mpw_strncasecmp( mpw_format_name( MPMarshalFormatJSON ), formatName, strlen( formatName ) ) == OK)
        return MPMarshalFormatJSON;

    dbg( "Not a format name: %s", formatName );
    return (MPMarshalFormat)ERR;
}

const char *mpw_format_name(
        const MPMarshalFormat format) {

    switch (format) {
        case MPMarshalFormatNone:
            return "none";
        case MPMarshalFormatFlat:
            return "flat";
        case MPMarshalFormatJSON:
            return "json";
        default: {
            dbg( "Unknown format: %d", format );
            return NULL;
        }
    }
}

const char *mpw_format_extension(
        const MPMarshalFormat format) {

    switch (format) {
        case MPMarshalFormatNone:
            return NULL;
        case MPMarshalFormatFlat:
            return "mpsites";
        case MPMarshalFormatJSON:
            return "mpjson";
        default: {
            dbg( "Unknown format: %d", format );
            return NULL;
        }
    }
}

const char **mpw_format_extensions(
        const MPMarshalFormat format, size_t *count) {

    *count = 0;
    switch (format) {
        case MPMarshalFormatNone:
            return NULL;
        case MPMarshalFormatFlat:
            return mpw_strings( count,
                    mpw_format_extension( format ), "mpsites.txt", "txt", NULL );
        case MPMarshalFormatJSON:
            return mpw_strings( count,
                    mpw_format_extension( format ), "mpsites.json", "json", NULL );
        default: {
            dbg( "Unknown format: %d", format );
            return NULL;
        }
    }
}
