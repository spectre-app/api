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

#include "mpw-util.h"

MP_LIBS_BEGIN
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <libgen.h>

#if MPW_CPERCIVA
#include <scrypt/crypto_scrypt.h>
#include <scrypt/sha256.h>
#elif MPW_SODIUM
#include "sodium.h"
#endif
#define AES_ECB 0
#define AES_CBC 1
#include "aes.h"
MP_LIBS_END

MPLogLevel mpw_verbosity = MPLogLevelInfo;
FILE *mpw_log_sink_file_target = NULL;

static MPLogSink **sinks;
static size_t sinks_count;

bool mpw_log_sink_register(MPLogSink *sink) {

    if (!mpw_realloc( &sinks, NULL, MPLogSink *, ++sinks_count )) {
        --sinks_count;
        return false;
    }

    sinks[sinks_count - 1] = sink;
    return true;
}

bool mpw_log_sink_unregister(MPLogSink *sink) {

    for (unsigned int r = 0; r < sinks_count; ++r) {
        if (sinks[r] == sink) {
            sinks[r] = NULL;
            return true;
        }
    }

    return false;
}

bool mpw_log_sink(MPLogLevel level, const char *file, int line, const char *function, const char *format, ...) {

    if (mpw_verbosity < level)
        return false;

    va_list args;
    va_start( args, format );
    bool sunk = mpw_log_vsink( level, file, line, function, format, args );
    va_end( args );

    return sunk;
}

static const char *mpw_log_formatter(MPLogEvent *event) {

    if (!event->formatted)
        event->formatted = mpw_vstr( event->format, event->args );

    return event->formatted;
}

bool mpw_log_vsink(MPLogLevel level, const char *file, int line, const char *function, const char *format, va_list args) {

    if (mpw_verbosity < level)
        return false;

    MPLogEvent event = {
            .occurrence = time( NULL ),
            .level = level,
            .file = file,
            .line = line,
            .function = function,
            .format = format,
            .args = args,
            .formatter = &mpw_log_formatter,
    };
    bool sunk = mpw_log_esink( &event );

    return sunk;
}

bool mpw_log_esink(MPLogEvent *event) {

    if (mpw_verbosity < event->level)
        return false;

    bool sunk = false;
    for (unsigned int s = 0; s < sinks_count; ++s) {
        MPLogSink *sink = sinks[s];

        if (sink)
            sunk |= sink( event );
    }
    if (!sunk)
        sunk = mpw_log_sink_file( event );

    if (event->level <= MPLogLevelWarning) {
        (void)event->level/* error breakpoint opportunity */;
    }
    mpw_free_string( &event->formatted );
    if (event->level <= MPLogLevelFatal)
        abort();

    return sunk;
}

bool mpw_log_sink_file(MPLogEvent *event) {

    if (!mpw_log_sink_file_target)
        mpw_log_sink_file_target = stderr;

    if (mpw_verbosity >= MPLogLevelDebug) {
        switch (event->level) {
            case MPLogLevelTrace:
                fprintf( mpw_log_sink_file_target, "[TRC] " );
                break;
            case MPLogLevelDebug:
                fprintf( mpw_log_sink_file_target, "[DBG] " );
                break;
            case MPLogLevelInfo:
                fprintf( mpw_log_sink_file_target, "[INF] " );
                break;
            case MPLogLevelWarning:
                fprintf( mpw_log_sink_file_target, "[WRN] " );
                break;
            case MPLogLevelError:
                fprintf( mpw_log_sink_file_target, "[ERR] " );
                break;
            case MPLogLevelFatal:
                fprintf( mpw_log_sink_file_target, "[FTL] " );
                break;
            default:
                fprintf( mpw_log_sink_file_target, "[???] " );
                break;
        }
    }

    fprintf( mpw_log_sink_file_target, "%s\n", event->formatter( event ) );
    return true;
}

void mpw_uint16(const uint16_t number, uint8_t buf[static 2]) {

    buf[0] = (uint8_t)((number >> 8L) & UINT8_MAX);
    buf[1] = (uint8_t)((number >> 0L) & UINT8_MAX);
}

void mpw_uint32(const uint32_t number, uint8_t buf[static 4]) {

    buf[0] = (uint8_t)((number >> 24) & UINT8_MAX);
    buf[1] = (uint8_t)((number >> 16) & UINT8_MAX);
    buf[2] = (uint8_t)((number >> 8L) & UINT8_MAX);
    buf[3] = (uint8_t)((number >> 0L) & UINT8_MAX);
}

void mpw_uint64(const uint64_t number, uint8_t buf[static 8]) {

    buf[0] = (uint8_t)((number >> 56) & UINT8_MAX);
    buf[1] = (uint8_t)((number >> 48) & UINT8_MAX);
    buf[2] = (uint8_t)((number >> 40) & UINT8_MAX);
    buf[3] = (uint8_t)((number >> 32) & UINT8_MAX);
    buf[4] = (uint8_t)((number >> 24) & UINT8_MAX);
    buf[5] = (uint8_t)((number >> 16) & UINT8_MAX);
    buf[6] = (uint8_t)((number >> 8L) & UINT8_MAX);
    buf[7] = (uint8_t)((number >> 0L) & UINT8_MAX);
}

const char **mpw_strings(size_t *count, const char *strings, ...) {

    *count = 0;
    size_t size = 0;
    const char **array = NULL;

    va_list args;
    va_start( args, strings );
    for (const char *string = strings; string; (string = va_arg( args, const char * ))) {
        size_t cursor = *count;

        if (!mpw_realloc( &array, &size, const char *, cursor + 1 )) {
            mpw_free( &array, size );
            break;
        }

        *count = size / sizeof( *array );
        array[cursor] = string;
    }
    va_end( args );

    return array;
}

bool mpw_push_buf(uint8_t **buffer, size_t *bufferSize, const uint8_t *pushBuffer, const size_t pushSize) {

    if (!buffer || !bufferSize || !pushBuffer || !pushSize)
        return false;
    if (*bufferSize == (size_t)ERR)
        // The buffer was marked as broken, it is missing a previous push.  Abort to avoid corrupt content.
        return false;

    if (!mpw_realloc( buffer, bufferSize, uint8_t, (*bufferSize + pushSize) / sizeof( uint8_t ) )) {
        // realloc failed, we can't push.  Mark the buffer as broken.
        mpw_free( buffer, *bufferSize );
        *bufferSize = (size_t)ERR;
        return false;
    }

    uint8_t *bufferOffset = *buffer + *bufferSize - pushSize;
    memcpy( bufferOffset, pushBuffer, pushSize );
    return true;
}

bool mpw_push_string(uint8_t **buffer, size_t *bufferSize, const char *pushString) {

    return pushString && mpw_push_buf( buffer, bufferSize, (const uint8_t *)pushString, strlen( pushString ) );
}

bool mpw_string_push(char **string, const char *pushString) {

    if (!string || !pushString)
        return false;

    // We overwrite an existing trailing NUL byte.
    return pushString && mpw_push_buf( (uint8_t **const)string, &((size_t){ *string? strlen( *string ): 0 }),
            (const uint8_t *)pushString, strlen( pushString ) + 1 );
}

bool mpw_string_pushf(char **string, const char *pushFormat, ...) {

    va_list args;
    va_start( args, pushFormat );
    const char *pushString = mpw_vstr( pushFormat, args );
    bool success = mpw_string_push( string, pushString );
    mpw_free_string( &pushString );
    va_end( args );

    return success;
}

bool mpw_push_int(uint8_t **buffer, size_t *bufferSize, const uint32_t pushInt) {

    uint8_t pushBuf[4 /* 32 / 8 */];
    mpw_uint32( pushInt, pushBuf );
    return mpw_push_buf( buffer, bufferSize, pushBuf, sizeof( pushBuf ) );
}

bool __mpw_realloc(void **buffer, size_t *bufferSize, const size_t targetSize) {

    if (!buffer)
        return false;
    if (*buffer && bufferSize && *bufferSize == targetSize)
        return true;

    void *newBuffer = realloc( *buffer, targetSize );
    if (!newBuffer)
        return false;

    *buffer = newBuffer;
    if (bufferSize)
        *bufferSize = targetSize;

    return true;
}

void mpw_zero(void *buffer, size_t bufferSize) {

    uint8_t *b = buffer;
    for (; bufferSize > 0; --bufferSize)
        *b++ = 0;
}

bool __mpw_free(void **buffer, const size_t bufferSize) {

    if (!buffer || !*buffer)
        return false;

    mpw_zero( *buffer, bufferSize );
    free( *buffer );
    *buffer = NULL;

    return true;
}

bool __mpw_free_string(char **string) {

    return string && *string && __mpw_free( (void **)string, strlen( *string ) );
}

bool __mpw_free_strings(char **strings, ...) {

    bool success = true;

    va_list args;
    va_start( args, strings );
    success &= mpw_free_string( strings );
    for (char **string; (string = va_arg( args, char ** ));)
        success &= mpw_free_string( string );
    va_end( args );

    return success;
}

bool mpw_kdf_scrypt(uint8_t *key, const size_t keySize, const uint8_t *secret, const size_t secretSize, const uint8_t *salt, const size_t saltSize,
        const uint64_t N, const uint32_t r, const uint32_t p) {

    if (!key || !keySize || !secret || !secretSize || !salt || !saltSize)
        return false;

#if MPW_CPERCIVA
    if (crypto_scrypt( (const void *)secret, strlen( secret ), salt, saltSize, N, r, p, key, keySize ) < 0) {
        return false;
    }
#elif MPW_SODIUM
    if (crypto_pwhash_scryptsalsa208sha256_ll( secret, secretSize, salt, saltSize, N, r, p, key, keySize ) != OK) {
        return false;
    }
#else
#error No crypto support for mpw_scrypt.
#endif

    return true;
}

bool mpw_kdf_blake2b(uint8_t *subkey, const size_t subkeySize, const uint8_t *key, const size_t keySize,
        const uint8_t *context, const size_t contextSize, const uint64_t id, const char *personal) {

    if (!subkey || !subkeySize || !key || !keySize) {
        errno = EINVAL;
        return false;
    }

#if MPW_SODIUM
    if (keySize < crypto_generichash_blake2b_KEYBYTES_MIN || keySize > crypto_generichash_blake2b_KEYBYTES_MAX ||
        subkeySize < crypto_generichash_blake2b_KEYBYTES_MIN || subkeySize > crypto_generichash_blake2b_KEYBYTES_MAX ||
        (personal && strlen( personal ) > crypto_generichash_blake2b_PERSONALBYTES)) {
        errno = EINVAL;
        return false;
    }

    uint8_t saltBuf[crypto_generichash_blake2b_SALTBYTES] = { 0 };
    if (id)
        mpw_uint64( id, saltBuf );

    uint8_t personalBuf[crypto_generichash_blake2b_PERSONALBYTES] = { 0 };
    if (personal && strlen( personal ))
        memcpy( personalBuf, personal, min( sizeof( personalBuf ), strlen( personal ) ) );

    if (crypto_generichash_blake2b_salt_personal( subkey, subkeySize, context, contextSize, key, keySize, saltBuf, personalBuf ) != OK)
        return false;
#else
#error No crypto support for mpw_kdf_blake2b.
#endif

    return true;
}

bool mpw_hash_hmac_sha256(uint8_t mac[static 32], const uint8_t *key, const size_t keySize, const uint8_t *message, const size_t messageSize) {

    if (!mac || !key || !keySize || !message || !messageSize)
        return false;

#if MPW_CPERCIVA
    HMAC_SHA256_Buf( key, keySize, message, messageSize, mac );
    return true;
#elif MPW_SODIUM
    crypto_auth_hmacsha256_state state;
    return crypto_auth_hmacsha256_init( &state, key, keySize ) == OK &&
           crypto_auth_hmacsha256_update( &state, message, messageSize ) == OK &&
           crypto_auth_hmacsha256_final( &state, mac ) == OK;
#else
#error No crypto support for mpw_hmac_sha256.
#endif
}

const static uint8_t *mpw_aes(bool encrypt, const uint8_t *key, const size_t keySize, const uint8_t *buf, size_t *bufSize) {

    if (!key || keySize < AES_BLOCK_SIZE || !bufSize || !*bufSize)
        return NULL;

    // IV = zero
    static const uint8_t iv[AES_BLOCK_SIZE] = { 0 };

    // Add PKCS#7 padding
    uint32_t aesSize = (uint32_t)*bufSize, blockRemainder = aesSize % AES_BLOCK_SIZE;
    if (blockRemainder) // round up to block size.
        aesSize += AES_BLOCK_SIZE - blockRemainder;
    else if (encrypt) // add pad block if plain text fits block size.
        aesSize += AES_BLOCK_SIZE;
    uint8_t *resultBuf = calloc( aesSize, sizeof( uint8_t ) );
    if (!resultBuf)
        return NULL;
    uint8_t *aesBuf = malloc( aesSize );
    if (!aesBuf) {
        mpw_free( &resultBuf, aesSize );
        return NULL;
    }

    memcpy( aesBuf, buf, *bufSize );
    memset( aesBuf + *bufSize, (int)(aesSize - *bufSize), aesSize - *bufSize );

    if (encrypt)
        AES_CBC_encrypt_buffer( resultBuf, aesBuf, aesSize, key, iv );
    else
        AES_CBC_decrypt_buffer( resultBuf, aesBuf, aesSize, key, iv );
    mpw_free( &aesBuf, aesSize );

    // Truncate PKCS#7 padding
    if (encrypt)
        *bufSize = aesSize;
    else if (resultBuf[aesSize - 1] <= AES_BLOCK_SIZE)
        *bufSize -= resultBuf[aesSize - 1];
    memset( resultBuf + *bufSize, 0, aesSize - *bufSize );

    return resultBuf;
}

const uint8_t *mpw_aes_encrypt(const uint8_t *key, const size_t keySize, const uint8_t *plainBuffer, size_t *bufferSize) {

    return mpw_aes( true, key, keySize, plainBuffer, bufferSize );
}

const uint8_t *mpw_aes_decrypt(const uint8_t *key, const size_t keySize, const uint8_t *cipherBuffer, size_t *bufferSize) {

    return mpw_aes( false, key, keySize, cipherBuffer, bufferSize );
}

#if UNUSED
const char *mpw_hotp(const uint8_t *key, size_t keySize, uint64_t movingFactor, uint8_t digits, uint8_t truncationOffset) {

    // Hash the moving factor with the key.
    uint8_t counter[8];
    mpw_uint64( movingFactor, counter );
    uint8_t hash[20];
    hmac_sha1( key, keySize, counter, sizeof( counter ), hash );

    // Determine the offset to select OTP bytes from.
    int offset;
    if ((truncationOffset >= 0) && (truncationOffset < (sizeof( hash ) - 4)))
        offset = truncationOffset;
    else
        offset = hash[sizeof( hash ) - 1] & 0xf;

    // Select four bytes from the truncation offset.
    uint32_t otp = 0U
            | ((hash[offset + 0] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | ((hash[offset + 3] & 0xff) << 0);

    // Render the OTP as `digits` decimal digits.
    otp %= (int)pow(10, digits);
    return mpw_strdup( mpw_str( "%0*d", digits, otp ) );
}
#endif

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

const char *mpw_str(const char *format, ...) {

    va_list args;
    va_start( args, format );
    const char *str = mpw_vstr( format, args );
    va_end( args );

    return str;
}

const char *mpw_vstr(const char *format, va_list args) {

    if (!format || !*format)
        return NULL;

    char *str = NULL;
    size_t size = 0;

    while (true) {
        va_list args_copy;
        va_copy( args_copy, args );
        size_t chars = (size_t)vsnprintf( str, size, format, args_copy );
        va_end( args_copy );

        if (chars < 0)
            break;
        if (chars < size)
            return str;
        if (!mpw_realloc( &str, &size, char, chars + 1 ))
            break;
    }

    mpw_free( &str, size );
    return NULL;
}

char *mpw_hex(const uint8_t *buf, const size_t size, char *hex, size_t *hexSize) {

    if (!buf || !size)
        return NULL;
    if (!mpw_realloc( &hex, hexSize, char, size * 2 + 1 ))
        return NULL;

    for (size_t kH = 0; kH < size; kH++)
        sprintf( &(hex[kH * 2]), "%.2hhX", buf[kH] );

    return hex;
}

const char *mpw_hex_l(const uint32_t number, char hex[static 9]) {

    uint8_t buf[4 /* 32 / 8 */];
    mpw_uint32( number, buf );

    size_t hexSize = 9;
    return mpw_hex( buf, sizeof( buf ), hex, &hexSize );
}

const uint8_t *mpw_unhex(const char *hex, size_t *size) {

    if (!hex)
        return NULL;

    size_t hexLength = strlen( hex );
    if (hexLength == 0 || hexLength % 2 != 0)
        return NULL;

    size_t bufSize = hexLength / 2;
    if (size)
        *size = bufSize;

    uint8_t *buf = malloc( bufSize );
    for (size_t b = 0; b < bufSize; ++b)
        if (sscanf( hex + b * 2, "%02hhX", &buf[b] ) != 1) {
            mpw_free( &buf, bufSize );
            return NULL;
        }

    return buf;
}

size_t mpw_utf8_char_size(const char *utf8String) {

    if (!utf8String)
        return 0U;

    // Legal UTF-8 byte sequences: <http://www.unicode.org/unicode/uni2errata/UTF-8_Corrigendum.html>
    unsigned char utf8Char = (unsigned char)*utf8String;
    if (utf8Char >= 0x00 && utf8Char <= 0x7F)
        return min( 1U, strlen( utf8String ) );
    if (utf8Char >= 0xC2 && utf8Char <= 0xDF)
        return min( 2U, strlen( utf8String ) );
    if (utf8Char >= 0xE0 && utf8Char <= 0xEF)
        return min( 3U, strlen( utf8String ) );
    if (utf8Char >= 0xF0 && utf8Char <= 0xF4)
        return min( 4U, strlen( utf8String ) );

    return 0U;
}

size_t mpw_utf8_char_count(const char *utf8String) {

    size_t strchars = 0, charlen;
    for (char *remaining = (char *)utf8String; remaining && *remaining; remaining += charlen, ++strchars)
        if (!(charlen = mpw_utf8_char_size( remaining )))
            return 0;

    return strchars;
}

void *mpw_memdup(const void *src, const size_t len) {

    if (!src)
        return NULL;

    char *dst = malloc( len );
    if (dst)
        memcpy( dst, src, len );

    return dst;
}

const char *mpw_strdup(const char *src) {

    if (!src)
        return NULL;

    size_t len = strlen( src );
    return mpw_memdup( src, len + 1 );
}

const char *mpw_strndup(const char *src, const size_t max) {

    if (!src)
        return NULL;

    size_t len = 0;
    for (; len < max && src[len] != '\0'; ++len);

    char *dst = calloc( len + 1, sizeof( char ) );
    if (dst)
        memcpy( dst, src, len );

    return dst;
}

int mpw_strcasecmp(const char *s1, const char *s2) {

    return mpw_strncasecmp( s1, s2, s1 && s2? min( strlen( s1 ), strlen( s2 ) ): 0 );
}

int mpw_strncasecmp(const char *s1, const char *s2, size_t max) {

    if (s1 == s2)
        return 0;

    int cmp = s1 && s2 && max > 0? 0: s1? 1: -1;
    for (; !cmp && max && max-- > 0 && s1 && s2; ++s1, ++s2)
        cmp = tolower( (unsigned char)*s1 ) - tolower( (unsigned char)*s2 );

    return cmp;
}
