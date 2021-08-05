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

#ifndef _SPECTRE_UTIL_H
#define _SPECTRE_UTIL_H

#include "spectre-types.h"

SPECTRE_LIBS_BEGIN
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
SPECTRE_LIBS_END

//// Logging.
///
/// spectre's log mechanism uses a layered approach:
/// 1. trc/dbg/inf/wrn/err/ftl macros initiate a log event.
///    They record metadata such as severity, source code and time. Events are recorded as a static message and a set of data arguments.
///    The log message should be a static printf(3)-style format string with compatible arguments.
/// 2. The macros are handled by the SPECTRE_LOG define, which defaults to spectre_log.
///    It should reference a symbol with the signature:
///    (bool) (SpectreLogLevel level, const char *file, int line, const char *function, const char *format, ... args)
/// 3. spectre_verbosity determines the severity threshold for log processing; any messages above its threshold are discarded.
///    This avoids triggering the log mechanism for events which are not considered interesting at the time.
/// 4. The spectre_log implementation consumes the log event through spectre's log sink mechanism.
///    The sink mechanism aims to make log messages available to any interested party.
///    Only if there are no interested parties registered, log events will be sunk into spectre_log_sink_file.
///    The return value can be used to check if the event was consumed by any sink.
/// 5. SpectreLogEvent values are created by spectre_log to host the log event data for relaying into log sinks.
///    All values come directly from the log event macros, with two exceptions:
///    .formatter is a function capable of merging the message format and data arguments into a complete log message.
///    .formatted is a heap allocated string representing the completely merged log message.
///    spectre_elog can be used to introduce events into the system which do not originate from the macros.
///    These events need to at a minimum provide a .formatter to ensure argument data can be merged into the format message.
/// 6. spectre_log_sink_register records an SpectreLogSink as interested in receiving subsequent log events.
///    Any events dispatched into the spectre_elog mechanism hence forth will be relayed into the newly registered log sink.
///    spectre_log_sink_unregister should be used when a sink is no longer interested in consuming log events.
/// 7. An SpectreLogSink consumes SpectreLogEvent values in whatever way it sees fit.
///    If a sink is interested in a complete formatted message, it should use .formatted, if available, or .formatter
///    to obtain the message (and then store it in .formatted for future sinks).
///    If for whatever reason the sink did not act on the message, it should return false.
/// 8. The default sink, spectre_log_sink_file, consumes log events by writing them to the spectre_log_sink_file_target FILE.
///    A log event's complete message is resolved through its .formatter, prefixed with its severity and terminated by a newline.
///    The default spectre_log_sink_file_target is stderr, yielding a default behaviour that writes log events to the system's standard error.

typedef spectre_enum( int, SpectreLogLevel ) {
    /** Logging internal state. */
    SpectreLogLevelTrace = 3,
    /** Logging state and events interesting when investigating issues. */
    SpectreLogLevelDebug = 2,
    /** User messages. */
    SpectreLogLevelInfo = 1,
    /** Recoverable issues and user suggestions. */
    SpectreLogLevelWarning = 0,
    /** Unrecoverable issues. */
    SpectreLogLevelError = -1,
    /** Issues that lead to abortion. */
    SpectreLogLevelFatal = -2,
};
extern SpectreLogLevel spectre_verbosity;

/** A log event describes a message emitted through the log subsystem. */
typedef struct SpectreLogEvent {
    time_t occurrence;
    SpectreLogLevel level;
    const char *file;
    int line;
    const char *function;
    /** @return A C-string (allocated), cached in .formatted, of the .args interpolated into the .format message. */
    const char *(*formatter)(struct SpectreLogEvent *);
    const char *formatted;
    const char *format;
    const va_list *args;
} SpectreLogEvent;

/** A log sink describes a function that can receive log events. */
typedef bool (SpectreLogSink)(SpectreLogEvent *event);

/** spectre_log_sink_file is a sink that writes log messages to the spectre_log_sink_file_target, which defaults to stderr. */
extern SpectreLogSink spectre_log_sink_file;
extern FILE *spectre_log_sink_file_target;

/** To receive events, sinks need to be registered.  If no sinks are registered, log events are sent to the spectre_log_sink_file sink. */
bool spectre_log_sink_register(SpectreLogSink *sink);
bool spectre_log_sink_unregister(SpectreLogSink *sink);

/** These functions dispatch log events to the registered sinks.
 * @return false if no sink processed the log event (sinks may reject messages or fail). */
bool spectre_log(SpectreLogLevel level, const char *file, int line, const char *function, const char *format, ...);
bool spectre_vlog(SpectreLogLevel level, const char *file, int line, const char *function, const char *format, va_list *args);
bool spectre_elog(SpectreLogEvent *event);

/** The log dispatcher you want to channel log messages into; defaults to spectre_log, enabling the log sink mechanism. */
#ifndef SPECTRE_LOG
#define SPECTRE_LOG spectre_log
#endif

/** Application interface for logging events into the subsystem. */
#ifndef trc
#define trc(format, ...) SPECTRE_LOG( SpectreLogLevelTrace, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__ )
#define dbg(format, ...) SPECTRE_LOG( SpectreLogLevelDebug, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__ )
#define inf(format, ...) SPECTRE_LOG( SpectreLogLevelInfo, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__ )
#define wrn(format, ...) SPECTRE_LOG( SpectreLogLevelWarning, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__ )
#define err(format, ...) SPECTRE_LOG( SpectreLogLevelError, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__ )
#define ftl(format, ...) SPECTRE_LOG( SpectreLogLevelFatal, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__ )
#endif


//// Utilities.

#ifndef OK
#define OK 0
#endif
#ifndef ERR
#define ERR -1
#endif

#ifndef stringify
#define stringify(s) #s
#endif
#ifndef stringify_def
#define stringify_def(s) stringify(s)
#endif

#if __GNUC__ >= 3
#ifndef min
#define min(a, b) ({ \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })
#endif
#ifndef max
#define max(a, b) ({ \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })
#endif
#define spectre_default(__default, __value) ({ __typeof__ (__value) _v = (__value); _v? _v: (__default); })
#define spectre_default_num(__default, __num) ({ __typeof__ (__num) _n = (__num); !isnan( _n )? (__typeof__ (__default))_n: (__default); })
#else
#ifndef min
#define min(a, b) ( (a) < (b) ? (a) : (b) )
#endif
#ifndef max
#define max(a, b) ( (a) > (b) ? (a) : (b) )
#endif
#define spectre_default(__default, __value) ( (__value)? (__value): (__default) )
#define spectre_default_num(__default, __num) ( !isnan( (__num) )? (__num): (__default) )
#endif


//// Buffers and memory.

/** Write a number to a byte buffer using spectre's endianness (big/network). */
void spectre_uint16(const uint16_t number, uint8_t buf[2]);
void spectre_uint32(const uint32_t number, uint8_t buf[4]);
void spectre_uint64(const uint64_t number, uint8_t buf[8]);

/** @return An array of strings (allocated, count) or NULL if no strings were given or we could not allocate space for the new array. */
const char **spectre_strings(
        size_t *count, const char *strings, ...);

/** Push a value onto a buffer.  The given buffer is realloc'ed and the value appended to the end of it.
 * @param buffer A pointer to the buffer (allocated, bufferSize) to append to. No-op if NULL. New buffer with value if NULL pointer.
 * @param value The object to append to the buffer.
 *              If char*, copies a C-string from the value.
 *              If uint8_t*, takes a size_t argument indicating the amount of uint8_t's to copy from the value. */
#define spectre_buf_push(buffer, bufferSize, value, ...) _Generic( (value), \
        uint32_t: spectre_buf_push_uint32,                                  \
        uint8_t *: spectre_buf_push_buf, const uint8_t *: spectre_buf_push_buf, \
        char *: spectre_buf_push_str, const char *: spectre_buf_push_str )      \
        ( buffer, bufferSize, value, ##__VA_ARGS__)
bool spectre_buf_push_buf(
        uint8_t **buffer, size_t *bufferSize, const uint8_t *pushBuffer, const size_t pushSize);
/** Push an integer onto a buffer.  reallocs the given buffer and appends the given integer using spectre's endianness (big/network).
 * @param buffer A pointer to the buffer (allocated, bufferSize) to append to, may be NULL. */
bool spectre_buf_push_uint32(
        uint8_t **buffer, size_t *bufferSize, const uint32_t pushInt);
/** Push a C-string onto a buffer.  reallocs the given buffer and appends the given string.
 * @param buffer A pointer to the buffer (allocated, bufferSize) to append to, may be NULL. */
bool spectre_buf_push_str(
        uint8_t **buffer, size_t *bufferSize, const char *pushString);

/** Push a C-string onto another string.  reallocs the target string and appends the source string.
 * @param string A pointer to the string (allocated) to append to, may be NULL. */
bool spectre_string_push(
        char **string, const char *pushString);
bool spectre_string_pushf(
        char **string, const char *pushFormat, ...);

// These defines merely exist to do type-checking, force the void** cast & drop any const qualifier.
/** Reallocate the given buffer from the given size by making space for the given amount of objects of the given type.
 * On success, the bufferSize pointer will be updated to the buffer's new byte size and the buffer pointer may be updated to a new memory address.
 * On failure, the pointers will remain unaffected.
 * @param buffer A pointer to the buffer (allocated, bufferSize) to reallocate.
 * @param bufferSize A pointer to the buffer's current size, or NULL.
 * @param targetSize The amount to reallocate the buffer's size into.
 * @return true if successful, false if reallocation failed.
 */
#define spectre_realloc(\
        /* const void** */buffer, /* size_t* */bufferSize, type, /* const size_t */typeCount) \
        ({ type **_buffer = buffer; __spectre_realloc( (void **)_buffer, bufferSize, sizeof( type ) * (typeCount) ); })
/** Free a buffer after zero'ing its contents, then set the reference to NULL.
 * @param bufferSize The byte-size of the buffer, these bytes will be zeroed prior to deallocation. */
#define spectre_free(\
        /* void** */buffer, /* size_t */ bufferSize) \
        ({ __typeof__(buffer) _b = buffer; const void *__b = *_b; (void)__b; __spectre_free( (void **)_b, bufferSize ); })
/** Free a C-string after zero'ing its contents, then set the reference to NULL. */
#define spectre_free_string(\
        /* char** */string) \
        ({ __typeof__(string) _s = string; const char *__s = *_s; (void)__s; __spectre_free_string( (char **)_s ); })
/** Free strings after zero'ing their contents, then set the references to NULL.  Terminate the va_list with NULL. */
#define spectre_free_strings(\
        /* char** */strings, ...) \
        ({ __typeof__(strings) _s = strings; const char *__s = *_s; (void)__s; __spectre_free_strings( (char **)_s, __VA_ARGS__ ); })
/** Free a C-string after zero'ing its contents, then set the reference to the replacement string.
 * The replacement string is generated before the original is freed; so it can be a derivative of the original. */
#define spectre_replace_string(\
        /* char* */string, /* char* */replacement) \
        do { const char *replacement_ = replacement; spectre_free_string( &string ); string = replacement_; } while (0)
#ifdef _MSC_VER
#undef spectre_realloc
#define spectre_realloc(buffer, bufferSize, targetSize) \
        __spectre_realloc( (void **)buffer, bufferSize, targetSize )
#undef spectre_free
#define spectre_free(buffer, bufferSize) \
        __spectre_free( (void **)buffer, bufferSize )
#undef spectre_free_string
#define spectre_free_string(string) \
        __spectre_free_string( (char **)string )
#undef spectre_free_strings
#define spectre_free_strings(strings, ...) \
        __spectre_free_strings( (char **)strings, __VA_ARGS__ )
#endif
bool __spectre_realloc(
        void **buffer, size_t *bufferSize, const size_t targetSize);
bool __spectre_free(
        void **buffer, size_t bufferSize);
bool __spectre_free_string(
        char **string);
bool __spectre_free_strings(
        char **strings, ...);
void spectre_zero(
        void *buffer, const size_t bufferSize);


//// Cryptography.

/** Derive a key from the given secret and salt using the scrypt KDF.
 * @return A buffer (allocated, keySize) containing the key or NULL if secret or salt is missing, key could not be allocated or the KDF failed. */
bool spectre_kdf_scrypt(
        uint8_t *key, const size_t keySize, const uint8_t *secret, const size_t secretSize, const uint8_t *salt, const size_t saltSize,
        const uint64_t N, const uint32_t r, const uint32_t p);
/** Derive a subkey from the given key using the blake2b KDF.
 * @return A buffer (allocated, keySize) containing the key or NULL if the key or subkeySize is missing, the key sizes are out of bounds, the subkey could not be allocated or derived. */
bool spectre_kdf_blake2b(
        uint8_t *subkey, const size_t subkeySize, const uint8_t *key, const size_t keySize,
        const uint8_t *context, const size_t contextSize, const uint64_t id, const char *personal);
/** Calculate the MAC for the given message with the given key using SHA256-HMAC.
 * @return A buffer (allocated, 32-byte) containing the MAC or NULL if the key or message is missing, the MAC could not be allocated or generated. */
bool spectre_hash_hmac_sha256(
        uint8_t mac[static 32], const uint8_t *key, const size_t keySize, const uint8_t *message, const size_t messageSize);
/** Encrypt a plainBuffer with the given key using AES-128-CBC.
 * @param bufferSize A pointer to the size of the plain buffer on input, and the size of the returned cipher buffer on output.
 * @return A buffer (allocated, bufferSize) containing the cipherBuffer or NULL if the key or buffer is missing, the key size is out of bounds or the result could not be allocated. */
const uint8_t *spectre_aes_encrypt(
        const uint8_t *key, const size_t keySize, const uint8_t *plainBuffer, size_t *bufferSize);
/** Decrypt a cipherBuffer with the given key using AES-128-CBC.
 * @param bufferSize A pointer to the size of the cipher buffer on input, and the size of the returned plain buffer on output.
 * @return A buffer (allocated, bufferSize) containing the plainBuffer or NULL if the key or buffer is missing, the key size is out of bounds or the result could not be allocated. */
const uint8_t *spectre_aes_decrypt(
        const uint8_t *key, const size_t keySize, const uint8_t *cipherBuffer, size_t *bufferSize);
#if UNUSED
/** Calculate an OTP using RFC-4226.
 * @return A C-string (allocated) containing exactly `digits` decimal OTP digits. */
const char *spectre_hotp(
        const uint8_t *key, size_t keySize, uint64_t movingFactor, uint8_t digits, uint8_t truncationOffset);
#endif


//// Encoding.

/** Compose a formatted string.
 * @return A C-string (allocated); or NULL if the format is missing or the result could not be allocated or formatted. */
const char *spectre_str(const char *format, ...);
const char *spectre_vstr(const char *format, va_list args);
/** Encode size-bytes from a buffer as a C-string of hexadecimal characters.
 * @param hex If not NULL, use it to store the hexadecimal characters.  Will be realloc'ed if it isn't large enough.  Result is returned.
 * @return A C-string (allocated, size * 2 + 1 bytes); NULL if the buffer is missing or the result could not be allocated. */
char *spectre_hex(const uint8_t *buf, const size_t size, char *hex, size_t *hexSize);
const char *spectre_hex_l(const uint32_t number, char hex[static 9]);
/** Decode a C-string of hexadecimal characters into a buffer of size-bytes.
 * @return A buffer (allocated, *size); or NULL if hex is NULL, empty, or not an even-length hexadecimal string. */
const uint8_t *spectre_unhex(const char *hex, size_t *size);

/** @return The amount of bytes needed to decode b64Length amount of base-64 characters. */
size_t spectre_base64_decode_max(size_t b64Length);
/** Decodes a base-64 encoded string into a byte buffer.
  * @param byteBuf a byte buffer, size should be at least spectre_base64_decode_max(strlen(b64Text))
  * @return The amount of bytes that were written to byteBuf or 0 if the base-64 string couldn't be fully decoded. */
size_t spectre_base64_decode(const char *b64Text, uint8_t *byteBuf);

/** @return The amount of bytes needed to encode a byteBuf of the given size as base-64 (including a terminating NUL). */
size_t spectre_base64_encode_max(size_t byteSize);
/** Encodes a byte buffer into a base-64 encoded string.
  * @param b64Text a character buffer, size should be at least spectre_base64_encode_max(byteSize)
  * @return The amount of characters that were written to b64Text, excluding the terminating NUL. */
size_t spectre_base64_encode(const uint8_t *byteBuf, size_t byteSize, char *b64Text);

/** @return The byte size of the UTF-8 character at the start of the given string or 0 if it is NULL, empty or not a legal UTF-8 character. */
size_t spectre_utf8_char_size(const char *utf8String);
/** @return The amount of UTF-8 characters in the given string or 0 if it is NULL, empty, or contains bytes that are not legal in UTF-8. */
size_t spectre_utf8_char_count(const char *utf8String);


//// Compatibility.

/** Drop-in for memdup(3).
 * @return A buffer (allocated, len) with len bytes copied from src or NULL if src is missing or the buffer could not be allocated. */
void *spectre_memdup(const void *src, const size_t len);
/** Drop-in for POSIX strdup(3).
 * @return A C-string (allocated) copied from src or NULL if src is missing or the buffer could not be allocated. */
const char *spectre_strdup(const char *src);
/** Drop-in for POSIX strndup(3).
 * @return A C-string (allocated) with no more than max bytes copied from src or NULL if src is missing or the buffer could not be allocated. */
const char *spectre_strndup(const char *src, const size_t max);
/** Drop-in for POSIX strcasecmp(3). */
int spectre_strcasecmp(const char *s1, const char *s2);
/** Drop-in for POSIX strncasecmp(3). */
int spectre_strncasecmp(const char *s1, const char *s2, const size_t max);

#endif // _SPECTRE_UTIL_H
