// =============================================================================
// Created by Maarten Billemont on 2014-12-20.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of Spectre.
// Spectre is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of Spectre's trademarks.
// =============================================================================

#include "spectre-util.h"

SPECTRE_LIBS_BEGIN
#include <string.h>
#include <ctype.h>
#include <errno.h>

#if SPECTRE_CPERCIVA
#include <scrypt/crypto_scrypt.h>
#include <scrypt/sha256.h>
#elif SPECTRE_SODIUM
#include "sodium.h"
#endif
#define ECB 0
#define CBC 1
#define CTR 0
#include "aes.h"
SPECTRE_LIBS_END

SpectreLogLevel spectre_verbosity = SpectreLogLevelInfo;
FILE *spectre_log_sink_file_target = NULL;

static SpectreLogSink **sinks;
static size_t sinks_count;

bool spectre_log_sink_register(SpectreLogSink *sink) {

    if (!spectre_realloc( &sinks, NULL, SpectreLogSink *, ++sinks_count )) {
        --sinks_count;
        return false;
    }

    sinks[sinks_count - 1] = sink;
    return true;
}

bool spectre_log_sink_unregister(SpectreLogSink *sink) {

    for (unsigned int r = 0; r < sinks_count; ++r) {
        if (sinks[r] == sink) {
            sinks[r] = NULL;
            return true;
        }
    }

    return false;
}

bool spectre_log(SpectreLogLevel level, const char *file, int line, const char *function, const char *format, ...) {

    if (spectre_verbosity < level)
        return false;

    va_list args;
    va_start( args, format );
    bool sunk = spectre_vlog( level, file, line, function, format, &args );
    va_end( args );

    return sunk;
}

static const char *spectre_log_formatter(SpectreLogEvent *event) {

    if (!event->formatted) {
        va_list args;
        va_copy( args, *(va_list *)event->args );
        event->formatted = spectre_vstr( event->format, args );
        va_end( args );
    }

    return event->formatted;
}

bool spectre_vlog(SpectreLogLevel level, const char *file, int line, const char *function, const char *format, va_list *args) {

    if (spectre_verbosity < level)
        return false;

    SpectreLogEvent event = {
            .occurrence = time( NULL ),
            .level = level,
            .file = file,
            .line = line,
            .function = function,
            .format = format,
            .args = args,
            .formatter = &spectre_log_formatter,
    };
    bool sunk = spectre_elog( &event );

    return sunk;
}

bool spectre_elog(SpectreLogEvent *event) {

    if (spectre_verbosity < event->level)
        return false;

    bool sunk = false;
    if (!sinks_count)
        sunk = spectre_log_sink_file( event );

    else
        for (unsigned int s = 0; s < sinks_count; ++s) {
            SpectreLogSink *sink = sinks[s];

            if (sink)
                sunk |= sink( event );
        }

    if (event->level <= SpectreLogLevelWarning) {
        (void)event->level/* error breakpoint opportunity */;
    }
    spectre_free_string( &event->formatted );
    if (event->level <= SpectreLogLevelFatal)
        abort();

    return sunk;
}

bool spectre_log_sink_file(SpectreLogEvent *event) {

    if (!spectre_log_sink_file_target)
        spectre_log_sink_file_target = stderr;

    if (spectre_verbosity >= SpectreLogLevelDebug) {
        switch (event->level) {
            case SpectreLogLevelTrace:
                fprintf( spectre_log_sink_file_target, "[TRC] " );
                break;
            case SpectreLogLevelDebug:
                fprintf( spectre_log_sink_file_target, "[DBG] " );
                break;
            case SpectreLogLevelInfo:
                fprintf( spectre_log_sink_file_target, "[INF] " );
                break;
            case SpectreLogLevelWarning:
                fprintf( spectre_log_sink_file_target, "[WRN] " );
                break;
            case SpectreLogLevelError:
                fprintf( spectre_log_sink_file_target, "[ERR] " );
                break;
            case SpectreLogLevelFatal:
                fprintf( spectre_log_sink_file_target, "[FTL] " );
                break;
            default:
                fprintf( spectre_log_sink_file_target, "[???] " );
                break;
        }
    }

    fprintf( spectre_log_sink_file_target, "%s\n", event->formatter( event ) );
    return true;
}

void spectre_uint16(const uint16_t number, uint8_t buf[static 2]) {

    buf[0] = (uint8_t)((number >> 8L) & UINT8_MAX);
    buf[1] = (uint8_t)((number >> 0L) & UINT8_MAX);
}

void spectre_uint32(const uint32_t number, uint8_t buf[static 4]) {

    buf[0] = (uint8_t)((number >> 24) & UINT8_MAX);
    buf[1] = (uint8_t)((number >> 16) & UINT8_MAX);
    buf[2] = (uint8_t)((number >> 8L) & UINT8_MAX);
    buf[3] = (uint8_t)((number >> 0L) & UINT8_MAX);
}

void spectre_uint64(const uint64_t number, uint8_t buf[static 8]) {

    buf[0] = (uint8_t)((number >> 56) & UINT8_MAX);
    buf[1] = (uint8_t)((number >> 48) & UINT8_MAX);
    buf[2] = (uint8_t)((number >> 40) & UINT8_MAX);
    buf[3] = (uint8_t)((number >> 32) & UINT8_MAX);
    buf[4] = (uint8_t)((number >> 24) & UINT8_MAX);
    buf[5] = (uint8_t)((number >> 16) & UINT8_MAX);
    buf[6] = (uint8_t)((number >> 8L) & UINT8_MAX);
    buf[7] = (uint8_t)((number >> 0L) & UINT8_MAX);
}

const char **spectre_strings(size_t *count, const char *strings, ...) {

    *count = 0;
    size_t size = 0;
    const char **array = NULL;

    va_list args;
    va_start( args, strings );
    for (const char *string = strings; string; (string = va_arg( args, const char * ))) {
        size_t cursor = *count;

        if (!spectre_realloc( &array, &size, const char *, cursor + 1 )) {
            spectre_free( &array, size );
            break;
        }

        *count = size / sizeof( *array );
        array[cursor] = string;
    }
    va_end( args );

    return array;
}

bool spectre_buf_push_buf(uint8_t **buffer, size_t *bufferSize, const uint8_t *pushBuffer, const size_t pushSize) {

    if (!buffer || !bufferSize || !pushBuffer || !pushSize)
        return false;
    if (*bufferSize == (size_t)ERR)
        // The buffer was marked as broken, it is missing a previous push.  Abort to avoid corrupt content.
        return false;

    if (!spectre_realloc( buffer, bufferSize, uint8_t, (*bufferSize + pushSize) / sizeof( uint8_t ) )) {
        // realloc failed, we can't push.  Mark the buffer as broken.
        spectre_free( buffer, *bufferSize );
        *bufferSize = (size_t)ERR;
        return false;
    }

    uint8_t *bufferOffset = *buffer + *bufferSize - pushSize;
    memcpy( bufferOffset, pushBuffer, pushSize );
    return true;
}

bool spectre_buf_push_uint32(uint8_t **buffer, size_t *bufferSize, const uint32_t pushInt) {

    uint8_t pushBuf[4 /* 32 / 8 */];
    spectre_uint32( pushInt, pushBuf );
    return spectre_buf_push( buffer, bufferSize, pushBuf, sizeof( pushBuf ) );
}

bool spectre_buf_push_str(uint8_t **buffer, size_t *bufferSize, const char *pushString) {

    return pushString && spectre_buf_push( buffer, bufferSize, (const uint8_t *)pushString, strlen( pushString ) );
}

bool spectre_string_push(char **string, const char *pushString) {

    if (!string || !pushString)
        return false;

    // We overwrite an existing trailing NUL byte.
    return pushString && spectre_buf_push( (uint8_t **const)string, &((size_t){ *string? strlen( *string ): 0 }),
            (const uint8_t *)pushString, strlen( pushString ) + 1 );
}

bool spectre_string_pushf(char **string, const char *pushFormat, ...) {

    va_list args;
    va_start( args, pushFormat );
    const char *pushString = spectre_vstr( pushFormat, args );
    bool success = spectre_string_push( string, pushString );
    spectre_free_string( &pushString );
    va_end( args );

    return success;
}

bool __spectre_realloc(void **buffer, size_t *bufferSize, const size_t targetSize) {

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

void spectre_zero(void *buffer, size_t bufferSize) {

    uint8_t *b = buffer;
    for (; bufferSize > 0; --bufferSize)
        *b++ = 0;
}

bool __spectre_free(void **buffer, const size_t bufferSize) {

    if (!buffer || !*buffer)
        return false;

    spectre_zero( *buffer, bufferSize );
    free( *buffer );
    *buffer = NULL;

    return true;
}

bool __spectre_free_string(char **string) {

    return string && *string && __spectre_free( (void **)string, strlen( *string ) );
}

bool __spectre_free_strings(char **strings, ...) {

    bool success = true;

    va_list args;
    va_start( args, strings );
    success &= spectre_free_string( strings );
    for (char **string; (string = va_arg( args, char ** ));)
        success &= spectre_free_string( string );
    va_end( args );

    return success;
}

bool spectre_kdf_scrypt(uint8_t *key, const size_t keySize, const uint8_t *secret, const size_t secretSize, const uint8_t *salt, const size_t saltSize,
        const uint64_t N, const uint32_t r, const uint32_t p) {

    if (!key || !keySize || !secret || !secretSize || !salt || !saltSize)
        return false;

#if SPECTRE_CPERCIVA
    if (crypto_scrypt( (const void *)secret, strlen( secret ), salt, saltSize, N, r, p, key, keySize ) < 0) {
        return false;
    }
#elif SPECTRE_SODIUM
    if (crypto_pwhash_scryptsalsa208sha256_ll( secret, secretSize, salt, saltSize, N, r, p, key, keySize ) != OK) {
        return false;
    }
#else
#error No crypto support for spectre_kdf_scrypt.
#endif

    return true;
}

bool spectre_kdf_blake2b(uint8_t *subkey, const size_t subkeySize, const uint8_t *key, const size_t keySize,
        const uint8_t *context, const size_t contextSize, const uint64_t id, const char *personal) {

    if (!subkey || !subkeySize || !key || !keySize) {
        errno = EINVAL;
        return false;
    }

#if SPECTRE_SODIUM
    if (keySize < crypto_generichash_blake2b_KEYBYTES_MIN || keySize > crypto_generichash_blake2b_KEYBYTES_MAX ||
        subkeySize < crypto_generichash_blake2b_KEYBYTES_MIN || subkeySize > crypto_generichash_blake2b_KEYBYTES_MAX ||
        (personal && strlen( personal ) > crypto_generichash_blake2b_PERSONALBYTES)) {
        errno = EINVAL;
        return false;
    }

    uint8_t saltBuf[crypto_generichash_blake2b_SALTBYTES] = { 0 };
    if (id)
        spectre_uint64( id, saltBuf );

    uint8_t personalBuf[crypto_generichash_blake2b_PERSONALBYTES] = { 0 };
    if (personal && strlen( personal ))
        memcpy( personalBuf, personal, min( sizeof( personalBuf ), strlen( personal ) ) );

    if (crypto_generichash_blake2b_salt_personal( subkey, subkeySize, context, contextSize, key, keySize, saltBuf, personalBuf ) != OK)
        return false;
#else
#error No crypto support for spectre_kdf_blake2b.
#endif

    return true;
}

bool spectre_hash_hmac_sha256(uint8_t mac[static 32], const uint8_t *key, const size_t keySize, const uint8_t *message, const size_t messageSize) {

    if (!mac || !key || !keySize || !message || !messageSize)
        return false;

#if SPECTRE_CPERCIVA
    HMAC_SHA256_Buf( key, keySize, message, messageSize, mac );
    return true;
#elif SPECTRE_SODIUM
    crypto_auth_hmacsha256_state state;
    return crypto_auth_hmacsha256_init( &state, key, keySize ) == OK &&
           crypto_auth_hmacsha256_update( &state, message, messageSize ) == OK &&
           crypto_auth_hmacsha256_final( &state, mac ) == OK;
#else
#error No crypto support for spectre_hash_hmac_sha256.
#endif
}

const static uint8_t *spectre_aes(bool encrypt, const uint8_t *key, const size_t keySize, const uint8_t *buf, size_t *bufSize) {

    if (!key || keySize < AES_BLOCKLEN || !bufSize || !*bufSize)
        return NULL;

    // IV = zero
    static const uint8_t iv[AES_BLOCKLEN] = { 0 };

    // Add PKCS#7 padding
    uint32_t aesSize = (uint32_t)*bufSize, blockRemainder = aesSize % AES_BLOCKLEN;
    if (blockRemainder) // round up to block size.
        aesSize += AES_BLOCKLEN - blockRemainder;
    else if (encrypt) // add pad block if plain text fits block size.
        aesSize += AES_BLOCKLEN;
//    uint8_t *resultBuf = calloc( aesSize, sizeof( uint8_t ) );
//    if (!resultBuf)
//        return NULL;
    uint8_t *aesBuf = malloc( aesSize );
    if (!aesBuf) {
//        spectre_free( &resultBuf, aesSize );
        return NULL;
    }

    memcpy( aesBuf, buf, *bufSize );
    memset( aesBuf + *bufSize, (int)(aesSize - *bufSize), aesSize - *bufSize );

    struct AES_ctx aes;
    AES_init_ctx_iv( &aes, key, iv );

    if (encrypt)
        AES_CBC_encrypt_buffer( &aes, aesBuf, aesSize );
    else
        AES_CBC_decrypt_buffer( &aes, aesBuf, aesSize );
//    spectre_free( &aesBuf, aesSize );

    // Truncate PKCS#7 padding
    if (encrypt)
        *bufSize = aesSize;
    else if (aesBuf[aesSize - 1] <= AES_BLOCKLEN)
        *bufSize -= aesBuf[aesSize - 1];
    memset( aesBuf + *bufSize, 0, aesSize - *bufSize );

    return aesBuf;
}

const uint8_t *spectre_aes_encrypt(const uint8_t *key, const size_t keySize, const uint8_t *plainBuffer, size_t *bufferSize) {

    return spectre_aes( true, key, keySize, plainBuffer, bufferSize );
}

const uint8_t *spectre_aes_decrypt(const uint8_t *key, const size_t keySize, const uint8_t *cipherBuffer, size_t *bufferSize) {

    return spectre_aes( false, key, keySize, cipherBuffer, bufferSize );
}

#if UNUSED
const char *spectre_hotp(const uint8_t *key, size_t keySize, uint64_t movingFactor, uint8_t digits, uint8_t truncationOffset) {

    // Hash the moving factor with the key.
    uint8_t counter[8];
    spectre_uint64( movingFactor, counter );
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
    return spectre_strdup( spectre_str( "%0*d", digits, otp ) );
}
#endif

const char *spectre_str(const char *format, ...) {

    va_list args;
    va_start( args, format );
    const char *str = spectre_vstr( format, args );
    va_end( args );

    return str;
}

const char *spectre_vstr(const char *format, va_list args) {

    if (!format || !*format)
        return NULL;

    char *str = NULL;
    size_t size = 0;

    while (true) {
        va_list _args;
        va_copy( _args, args );
        size_t chars = (size_t)vsnprintf( str, size, format, _args );
        va_end( _args );

        if (chars < 0)
            break;
        if (chars < size)
            return str;
        if (!spectre_realloc( &str, &size, char, chars + 1 ))
            break;
    }

    spectre_free( &str, size );
    return NULL;
}

char *spectre_hex(const uint8_t *buf, const size_t size, char *hex, size_t *hexSize) {

    if (!buf || !size)
        return NULL;
    if (!spectre_realloc( &hex, hexSize, char, size * 2 + 1 ))
        return NULL;

    for (size_t kH = 0; kH < size; kH++)
        sprintf( &(hex[kH * 2]), "%.2hhX", buf[kH] );

    return hex;
}

const char *spectre_hex_l(const uint32_t number, char hex[static 9]) {

    uint8_t buf[4 /* 32 / 8 */];
    spectre_uint32( number, buf );

    size_t hexSize = 9;
    return spectre_hex( buf, sizeof( buf ), hex, &hexSize );
}

const uint8_t *spectre_unhex(const char *hex, size_t *size) {

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
            spectre_free( &buf, bufSize );
            return NULL;
        }

    return buf;
}

size_t spectre_base64_decode_max(size_t b64Length) {

    // Every 4 b64 chars yield 3 plain bytes => len = 3 * ceil(b64Size / 4)
    return 3 /*bytes*/ * ((b64Length + 4 /*chars*/ - 1) / 4 /*chars*/);
}

size_t spectre_base64_decode(const char *b64Text, uint8_t *byteBuf) {

    size_t b64Length = strlen( b64Text ), plainSize = 0;
    if (sodium_base642bin( byteBuf, spectre_base64_decode_max( b64Length ), b64Text, b64Length,
            " \n\r\t\v", &plainSize, NULL, sodium_base64_VARIANT_ORIGINAL ) == ERR)
        return 0;

    return plainSize;
}

size_t spectre_base64_encode_max(size_t byteSize) {

    return sodium_base64_ENCODED_LEN( byteSize, sodium_base64_VARIANT_ORIGINAL );
}

size_t spectre_base64_encode(const uint8_t *byteBuf, size_t byteSize, char *b64Text) {

    return strlen(
            sodium_bin2base64(
                    b64Text, spectre_base64_encode_max( byteSize ),
                    byteBuf, byteSize, sodium_base64_VARIANT_ORIGINAL ) );
}

size_t spectre_utf8_char_size(const char *utf8String) {

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

size_t spectre_utf8_char_count(const char *utf8String) {

    size_t strchars = 0, charlen;
    for (char *remaining = (char *)utf8String; remaining && *remaining; remaining += charlen, ++strchars)
        if (!(charlen = spectre_utf8_char_size( remaining )))
            return 0;

    return strchars;
}

void *spectre_memdup(const void *src, const size_t len) {

    if (!src)
        return NULL;

    char *dst = malloc( len );
    if (dst)
        memcpy( dst, src, len );

    return dst;
}

const char *spectre_strdup(const char *src) {

    if (!src)
        return NULL;

    size_t len = strlen( src );
    return spectre_memdup( src, len + 1 );
}

const char *spectre_strndup(const char *src, const size_t max) {

    if (!src)
        return NULL;

    size_t len = 0;
    for (; len < max && src[len] != '\0'; ++len);

    char *dst = calloc( len + 1, sizeof( char ) );
    if (dst)
        memcpy( dst, src, len );

    return dst;
}

int spectre_strcasecmp(const char *s1, const char *s2) {

    return spectre_strncasecmp( s1, s2, s1 && s2? min( strlen( s1 ), strlen( s2 ) ): 0 );
}

int spectre_strncasecmp(const char *s1, const char *s2, size_t max) {

    if (s1 == s2)
        return 0;

    int cmp = s1 && s2 && max > 0? 0: s1? 1: -1;
    for (; !cmp && max && max-- > 0 && s1 && s2; ++s1, ++s2)
        cmp = tolower( (unsigned char)*s1 ) - tolower( (unsigned char)*s2 );

    return cmp;
}
