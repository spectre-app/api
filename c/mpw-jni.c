#include <string.h>

#include "java/com_lyndir_masterpassword_MPAlgorithm_Version.h"

#include "spectre-algorithm.h"
#include "spectre-util.h"

// TODO: We may need to zero the jbytes safely.

static JavaVM *_vm;
static jobject logger;

SpectreLogSink spectre_log_sink_jni;

bool spectre_log_sink_jni(const SpectreLogEvent *record) {

    bool sunk = false;

    JNIEnv *env;
    if ((*_vm)->GetEnv( _vm, (void **)&env, JNI_VERSION_1_6 ) != JNI_OK)
        return sunk;

    if (logger && (*env)->PushLocalFrame( env, 16 ) == OK) {
        jmethodID method = NULL;
        jclass cLogger = (*env)->GetObjectClass( env, logger );
        switch (record->level) {
            case SpectreLogLevelTrace:
                method = (*env)->GetMethodID( env, cLogger, "trace", "(Ljava/lang/String;)V" );
                break;
            case SpectreLogLevelDebug:
                method = (*env)->GetMethodID( env, cLogger, "debug", "(Ljava/lang/String;)V" );
                break;
            case SpectreLogLevelInfo:
                method = (*env)->GetMethodID( env, cLogger, "info", "(Ljava/lang/String;)V" );
                break;
            case SpectreLogLevelWarning:
                method = (*env)->GetMethodID( env, cLogger, "warn", "(Ljava/lang/String;)V" );
                break;
            case SpectreLogLevelError:
            case SpectreLogLevelFatal:
                method = (*env)->GetMethodID( env, cLogger, "error", "(Ljava/lang/String;)V" );
                break;
        }

        if (method && record->message) {
            // TODO: log file, line & function as markers?
            (*env)->CallVoidMethod( env, logger, method, (*env)->NewStringUTF( env, record->message ) );
            sunk = true;
        }

        (*env)->PopLocalFrame( env, NULL );
    }

    return sunk;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {

    JNIEnv *env;
    if ((*vm)->GetEnv( _vm = vm, (void **)&env, JNI_VERSION_1_6 ) != JNI_OK)
        return -1;

    do {
        jclass cLoggerFactory = (*env)->FindClass( env, "org/slf4j/LoggerFactory" );
        if (!cLoggerFactory)
            break;
        jmethodID method = (*env)->GetStaticMethodID( env, cLoggerFactory, "getLogger", "(Ljava/lang/String;)Lorg/slf4j/Logger;" );
        if (!method)
            break;
        jstring name = (*env)->NewStringUTF( env, "com.lyndir.masterpassword.algorithm" );
        if (!name)
            break;
        logger = (*env)->NewGlobalRef( env, (*env)->CallStaticObjectMethod( env, cLoggerFactory, method, name ) );
        if (!logger)
            break;

        jclass cLogger = (*env)->GetObjectClass( env, logger );
        if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isTraceEnabled", "()Z" ) ))
            spectre_verbosity = SpectreLogLevelTrace;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isDebugEnabled", "()Z" ) ))
            spectre_verbosity = SpectreLogLevelDebug;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isInfoEnabled", "()Z" ) ))
            spectre_verbosity = SpectreLogLevelInfo;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isWarnEnabled", "()Z" ) ))
            spectre_verbosity = SpectreLogLevelWarning;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isErrorEnabled", "()Z" ) ))
            spectre_verbosity = SpectreLogLevelError;
        else
            spectre_verbosity = SpectreLogLevelFatal;

        spectre_log_sink_register( &spectre_log_sink_jni );
    } while (false);

    if (!logger)
        wrn( "Couldn't initialize JNI logger." );

    return JNI_VERSION_1_6;
}

/* native byte[] _userKey(final String userName, final byte[] userSecret, final int algorithmVersion) */
JNIEXPORT jbyteArray JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1userKey(JNIEnv *env, jobject obj,
        jstring userName, jbyteArray userSecret, jint algorithmVersion) {

#error TODO
    if (!userName || !userSecret)
        return NULL;

    const char *userNameString = (*env)->GetStringUTFChars( env, userName, NULL );
    jbyte *userSecretString = (*env)->GetByteArrayElements( env, userSecret, NULL );

    SpectreUserKey *userKeyBytes = spectre_user_key( userNameString, (char *)userSecretString, (SpectreAlgorithm)algorithmVersion );
    (*env)->ReleaseStringUTFChars( env, userName, userNameString );
    (*env)->ReleaseByteArrayElements( env, userSecret, userSecretString, JNI_ABORT );

    if (!userKeyBytes)
        return NULL;

    jbyteArray userKey = (*env)->NewByteArray( env, (jsize)sizeof( userKeyBytes->bytes ) );
    (*env)->SetByteArrayRegion( env, userKey, 0, (jsize)sizeof( userKeyBytes->bytes ), (jbyte *)userKeyBytes );
    spectre_free( &userKeyBytes, sizeof( userKeyBytes->bytes ) );

    return userKey;
}

/* native byte[] _siteKey(final byte[] userKey, final String siteName, final long keyCounter,
                          final int keyPurpose, @Nullable final String keyContext, final int version) */
JNIEXPORT jbyteArray JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1siteKey(JNIEnv *env, jobject obj,
        jbyteArray userKey, jstring siteName, jlong keyCounter, jint keyPurpose, jstring keyContext, jint algorithmVersion) {

#error TODO
    if (!userKey || !siteName)
        return NULL;

    jbyte *userKeyBytes = (*env)->GetByteArrayElements( env, userKey, NULL );
    const char *siteNameString = (*env)->GetStringUTFChars( env, siteName, NULL );
    const char *keyContextString = keyContext? (*env)->GetStringUTFChars( env, keyContext, NULL ): NULL;
    SpectreSiteKey siteKeyBytes = spectre_site_key(
            (SpectreUserKey)userKeyBytes, siteNameString, (SpectreCounter)keyCounter,
            (SpectreKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, userKey, userKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, siteName, siteNameString );
    if (keyContext)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );

    if (!siteKeyBytes)
        return NULL;

    jbyteArray siteKey = (*env)->NewByteArray( env, (jsize)sizeof( *userKey ) );
    (*env)->SetByteArrayRegion( env, siteKey, 0, (jsize)sizeof( *userKey ), (jbyte *)siteKeyBytes );
    spectre_free( &siteKeyBytes, sizeof( *siteKey ) );

    return siteKey;
}

/* native String _siteResult(final byte[] userKey, final byte[] siteKey, final String siteName, final long keyCounter,
                             final int keyPurpose, @Nullable final String keyContext,
                             final int resultType, @Nullable final String resultParam, final int algorithmVersion) */
JNIEXPORT jstring JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1siteResult(JNIEnv *env, jobject obj,
        jbyteArray userKey, jbyteArray siteKey, jstring siteName, jlong keyCounter, jint keyPurpose, jstring keyContext,
        jint resultType, jstring resultParam, jint algorithmVersion) {

#error TODO
    if (!userKey || !siteKey || !siteName)
        return NULL;

    jbyte *userKeyBytes = (*env)->GetByteArrayElements( env, userKey, NULL );
    jbyte *siteKeyBytes = (*env)->GetByteArrayElements( env, siteKey, NULL );
    const char *siteNameString = (*env)->GetStringUTFChars( env, siteName, NULL );
    const char *keyContextString = keyContext? (*env)->GetStringUTFChars( env, keyContext, NULL ): NULL;
    const char *resultParamString = resultParam? (*env)->GetStringUTFChars( env, resultParam, NULL ): NULL;
    const char *siteResultString = spectre_site_result( (SpectreUserKey)userKeyBytes, siteNameString,
            (SpectreResultType)resultType, resultParamString, (SpectreCounter)keyCounter, (SpectreKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, userKey, userKeyBytes, JNI_ABORT );
    (*env)->ReleaseByteArrayElements( env, siteKey, siteKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, siteName, siteNameString );
    if (keyContext)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );
    if (resultParam)
        (*env)->ReleaseStringUTFChars( env, resultParam, resultParamString );

    if (!siteResultString)
        return NULL;

    jstring siteResult = (*env)->NewStringUTF( env, siteResultString );
    spectre_free_string( &siteResultString );

    return siteResult;
}

/* native String _siteState(final byte[] userKey, final byte[] siteKey, final String siteName, final long keyCounter,
                            final int keyPurpose, @Nullable final String keyContext,
                            final int resultType, final String resultParam, final int algorithmVersion) */
JNIEXPORT jstring JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1siteState(JNIEnv *env, jobject obj,
        jbyteArray userKey, jbyteArray siteKey, jstring siteName, jlong keyCounter, jint keyPurpose, jstring keyContext,
        jint resultType, jstring resultParam, jint algorithmVersion) {

#error TODO
    if (!userKey || !siteKey || !siteName || !resultParam)
        return NULL;

    jbyte *userKeyBytes = (*env)->GetByteArrayElements( env, userKey, NULL );
    jbyte *siteKeyBytes = (*env)->GetByteArrayElements( env, siteKey, NULL );
    const char *siteNameString = (*env)->GetStringUTFChars( env, siteName, NULL );
    const char *keyContextString = keyContext? (*env)->GetStringUTFChars( env, keyContext, NULL ): NULL;
    const char *resultParamString = (*env)->GetStringUTFChars( env, resultParam, NULL );
    const char *siteStateString = spectre_site_state(
            (SpectreUserKey)userKeyBytes, siteNameString, (SpectreResultType)resultType, resultParamString, (SpectreCounter)keyCounter,
            (SpectreKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, userKey, userKeyBytes, JNI_ABORT );
    (*env)->ReleaseByteArrayElements( env, siteKey, siteKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, siteName, siteNameString );
    if (keyContextString)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );
    if (resultParam)
        (*env)->ReleaseStringUTFChars( env, resultParam, resultParamString );

    if (!siteStateString)
        return NULL;

    jstring siteState = (*env)->NewStringUTF( env, siteStateString );
    spectre_free_string( &siteStateString );

    return siteState;
}

/* native SpectreIdenticon _identicon(final String userName, final byte[] userSecret) */
JNIEXPORT jobject JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1identicon(JNIEnv *env, jobject obj,
        jstring userName, jbyteArray userSecret) {

#error TODO
    if (!userName || !userSecret)
        return NULL;

    const char *userNameString = (*env)->GetStringUTFChars( env, userName, NULL );
    jbyte *userSecretString = (*env)->GetByteArrayElements( env, userSecret, NULL );

    SpectreIdenticon identicon = spectre_identicon( userNameString, (char *)userSecretString );
    (*env)->ReleaseStringUTFChars( env, userName, userNameString );
    (*env)->ReleaseByteArrayElements( env, userSecret, userSecretString, JNI_ABORT );
    if (identicon.color == SpectreIdenticonColorUnset)
        return NULL;

    jclass cspectre_identicon_color = (*env)->FindClass( env, "com/lyndir/masterpassword/spectre_identicon$Color" );
    if (!cspectre_identicon_color)
        return NULL;
    jmethodID method = (*env)->GetStaticMethodID( env, cspectre_identicon_color, "values", "()[Lcom/lyndir/masterpassword/spectre_identicon$Color;" );
    if (!method)
        return NULL;
    jobject values = (*env)->CallStaticObjectMethod( env, cspectre_identicon_color, method );
    if (!values)
        return NULL;

    jclass cspectre_identicon = (*env)->FindClass( env, "com/lyndir/masterpassword/SpectreIdenticon" );
    if (!cspectre_identicon)
        return NULL;
    jmethodID init = (*env)->GetMethodID( env, cspectre_identicon, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/lyndir/masterpassword/spectre_identicon$Color;)V" );
    if (!init)
        return NULL;

    return (*env)->NewObject( env, cspectre_identicon, init, userName,
            (*env)->NewStringUTF( env, identicon.leftArm ),
            (*env)->NewStringUTF( env, identicon.body ),
            (*env)->NewStringUTF( env, identicon.rightArm ),
            (*env)->NewStringUTF( env, identicon.accessory ),
            (*env)->GetObjectArrayElement( env, values, identicon.color ) );
}

/* native String _toID(final byte[] buffer) */
JNIEXPORT jstring JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1toID(JNIEnv *env, jobject obj,
        jbyteArray buffer) {

#error TODO
    return (*env)->NewStringUTF( env, spectre_id_buf( (*env)->GetByteArrayElements( env, buffer, NULL ), (*env)->GetArrayLength( env, buffer ) ) );
}
