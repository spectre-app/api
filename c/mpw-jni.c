#include <string.h>

#include "java/com_lyndir_masterpassword_MPAlgorithm_Version.h"

#include "mpw-algorithm.h"
#include "mpw-util.h"

// TODO: We may need to zero the jbytes safely.

static JavaVM* _vm;
static jobject logger;

MPLogSink mpw_log_sink_jni;
bool mpw_log_sink_jni(const MPLogEvent *record) {
    bool sunk = false;

    JNIEnv *env;
    if ((*_vm)->GetEnv( _vm, (void **)&env, JNI_VERSION_1_6 ) != JNI_OK)
        return sunk;

    if (logger && (*env)->PushLocalFrame( env, 16 ) == OK) {
        jmethodID method = NULL;
        jclass cLogger = (*env)->GetObjectClass( env, logger );
        switch (record->level) {
            case MPLogLevelTrace:
                method = (*env)->GetMethodID( env, cLogger, "trace", "(Ljava/lang/String;)V" );
                break;
            case MPLogLevelDebug:
                method = (*env)->GetMethodID( env, cLogger, "debug", "(Ljava/lang/String;)V" );
                break;
            case MPLogLevelInfo:
                method = (*env)->GetMethodID( env, cLogger, "info", "(Ljava/lang/String;)V" );
                break;
            case MPLogLevelWarning:
                method = (*env)->GetMethodID( env, cLogger, "warn", "(Ljava/lang/String;)V" );
                break;
            case MPLogLevelError:
            case MPLogLevelFatal:
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

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
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
            mpw_verbosity = MPLogLevelTrace;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isDebugEnabled", "()Z" ) ))
            mpw_verbosity = MPLogLevelDebug;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isInfoEnabled", "()Z" ) ))
            mpw_verbosity = MPLogLevelInfo;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isWarnEnabled", "()Z" ) ))
            mpw_verbosity = MPLogLevelWarning;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isErrorEnabled", "()Z" ) ))
            mpw_verbosity = MPLogLevelError;
        else
            mpw_verbosity = MPLogLevelFatal;

        mpw_log_sink_register( &mpw_log_sink_jni );
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

    MPUserKey *userKeyBytes = mpw_user_key( userNameString, (char *)userSecretString, (MPAlgorithmVersion)algorithmVersion );
    (*env)->ReleaseStringUTFChars( env, userName, userNameString );
    (*env)->ReleaseByteArrayElements( env, userSecret, userSecretString, JNI_ABORT );

    if (!userKeyBytes)
        return NULL;

    jbyteArray userKey = (*env)->NewByteArray( env, (jsize)sizeof( userKeyBytes->bytes ) );
    (*env)->SetByteArrayRegion( env, userKey, 0, (jsize)sizeof( userKeyBytes->bytes ), (jbyte *)userKeyBytes );
    mpw_free( &userKeyBytes, sizeof( userKeyBytes->bytes ) );

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
    MPsiteKey siteKeyBytes = mpw_site_key(
            (MPUserKey)userKeyBytes, siteNameString, (MPCounterValue)keyCounter,
            (MPKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, userKey, userKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, siteName, siteNameString );
    if (keyContext)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );

    if (!siteKeyBytes)
        return NULL;

    jbyteArray siteKey = (*env)->NewByteArray( env, (jsize)sizeof( *userKey ) );
    (*env)->SetByteArrayRegion( env, siteKey, 0, (jsize)sizeof( *userKey ), (jbyte *)siteKeyBytes );
    mpw_free( &siteKeyBytes, sizeof( *siteKey ) );

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
    const char *siteResultString = mpw_site_result( (MPUserKey)userKeyBytes, siteNameString,
            (MPResultType)resultType, resultParamString, (MPCounterValue)keyCounter, (MPKeyPurpose)keyPurpose, keyContextString );
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
    mpw_free_string( &siteResultString );

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
    const char *siteStateString = mpw_site_state(
            (MPUserKey)userKeyBytes, siteNameString, (MPResultType)resultType, resultParamString, (MPCounterValue)keyCounter,
            (MPKeyPurpose)keyPurpose, keyContextString );
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
    mpw_free_string( &siteStateString );

    return siteState;
}

/* native MPIdenticon _identicon(final String userName, final byte[] userSecret) */
JNIEXPORT jobject JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1identicon(JNIEnv *env, jobject obj,
        jstring userName, jbyteArray userSecret) {
#error TODO
    if (!userName || !userSecret)
        return NULL;

    const char *userNameString = (*env)->GetStringUTFChars( env, userName, NULL );
    jbyte *userSecretString = (*env)->GetByteArrayElements( env, userSecret, NULL );

    MPIdenticon identicon = mpw_identicon( userNameString, (char *)userSecretString );
    (*env)->ReleaseStringUTFChars( env, userName, userNameString );
    (*env)->ReleaseByteArrayElements( env, userSecret, userSecretString, JNI_ABORT );
    if (identicon.color == MPIdenticonColorUnset)
        return NULL;

    jclass cMPIdenticonColor = (*env)->FindClass( env, "com/lyndir/masterpassword/MPIdenticon$Color" );
    if (!cMPIdenticonColor)
        return NULL;
    jmethodID method = (*env)->GetStaticMethodID( env, cMPIdenticonColor, "values", "()[Lcom/lyndir/masterpassword/MPIdenticon$Color;" );
    if (!method)
        return NULL;
    jobject values = (*env)->CallStaticObjectMethod( env, cMPIdenticonColor, method );
    if (!values)
        return NULL;

    jclass cMPIdenticon = (*env)->FindClass( env, "com/lyndir/masterpassword/MPIdenticon" );
    if (!cMPIdenticon)
        return NULL;
    jmethodID init = (*env)->GetMethodID( env, cMPIdenticon, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/lyndir/masterpassword/MPIdenticon$Color;)V" );
    if (!init)
        return NULL;

    return (*env)->NewObject( env, cMPIdenticon, init, userName,
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
    return (*env)->NewStringUTF( env, mpw_id_buf( (*env)->GetByteArrayElements( env, buffer, NULL ), (*env)->GetArrayLength( env, buffer ) ) );
}
