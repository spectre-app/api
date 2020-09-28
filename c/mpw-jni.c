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
            case LogLevelTrace:
                method = (*env)->GetMethodID( env, cLogger, "trace", "(Ljava/lang/String;)V" );
                break;
            case LogLevelDebug:
                method = (*env)->GetMethodID( env, cLogger, "debug", "(Ljava/lang/String;)V" );
                break;
            case LogLevelInfo:
                method = (*env)->GetMethodID( env, cLogger, "info", "(Ljava/lang/String;)V" );
                break;
            case LogLevelWarning:
                method = (*env)->GetMethodID( env, cLogger, "warn", "(Ljava/lang/String;)V" );
                break;
            case LogLevelError:
            case LogLevelFatal:
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
            mpw_verbosity = LogLevelTrace;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isDebugEnabled", "()Z" ) ))
            mpw_verbosity = LogLevelDebug;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isInfoEnabled", "()Z" ) ))
            mpw_verbosity = LogLevelInfo;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isWarnEnabled", "()Z" ) ))
            mpw_verbosity = LogLevelWarning;
        else if ((*env)->CallBooleanMethod( env, logger, (*env)->GetMethodID( env, cLogger, "isErrorEnabled", "()Z" ) ))
            mpw_verbosity = LogLevelError;
        else
            mpw_verbosity = LogLevelFatal;

        mpw_log_sink_register( &mpw_log_sink_jni );
    } while (false);

    if (!logger)
        wrn( "Couldn't initialize JNI logger." );

    return JNI_VERSION_1_6;
}

/* native byte[] _masterKey(final String fullName, final byte[] masterPassword, final int algorithmVersion) */
JNIEXPORT jbyteArray JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1masterKey(JNIEnv *env, jobject obj,
        jstring fullName, jbyteArray masterPassword, jint algorithmVersion) {
#error TODO
    if (!fullName || !masterPassword)
        return NULL;

    const char *fullNameString = (*env)->GetStringUTFChars( env, fullName, NULL );
    jbyte *masterPasswordString = (*env)->GetByteArrayElements( env, masterPassword, NULL );

    MPMasterKey *masterKeyBytes = mpw_master_key( fullNameString, (char *)masterPasswordString, (MPAlgorithmVersion)algorithmVersion );
    (*env)->ReleaseStringUTFChars( env, fullName, fullNameString );
    (*env)->ReleaseByteArrayElements( env, masterPassword, masterPasswordString, JNI_ABORT );

    if (!masterKeyBytes)
        return NULL;

    jbyteArray masterKey = (*env)->NewByteArray( env, (jsize)sizeof( masterKeyBytes->bytes ) );
    (*env)->SetByteArrayRegion( env, masterKey, 0, (jsize)sizeof( masterKeyBytes->bytes ), (jbyte *)masterKeyBytes );
    mpw_free( &masterKeyBytes, sizeof( masterKeyBytes->bytes ) );

    return masterKey;
}

/* native byte[] _serviceKey(final byte[] masterKey, final String serviceName, final long keyCounter,
                          final int keyPurpose, @Nullable final String keyContext, final int version) */
JNIEXPORT jbyteArray JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1serviceKey(JNIEnv *env, jobject obj,
        jbyteArray masterKey, jstring serviceName, jlong keyCounter, jint keyPurpose, jstring keyContext, jint algorithmVersion) {
#error TODO
    if (!masterKey || !serviceName)
        return NULL;

    jbyte *masterKeyBytes = (*env)->GetByteArrayElements( env, masterKey, NULL );
    const char *serviceNameString = (*env)->GetStringUTFChars( env, serviceName, NULL );
    const char *keyContextString = keyContext? (*env)->GetStringUTFChars( env, keyContext, NULL ): NULL;
    MPServiceKey serviceKeyBytes = mpw_service_key(
            (MPMasterKey)masterKeyBytes, serviceNameString, (MPCounterValue)keyCounter,
            (MPKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, masterKey, masterKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, serviceName, serviceNameString );
    if (keyContext)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );

    if (!serviceKeyBytes)
        return NULL;

    jbyteArray serviceKey = (*env)->NewByteArray( env, (jsize)sizeof( *masterKey ) );
    (*env)->SetByteArrayRegion( env, serviceKey, 0, (jsize)sizeof( *masterKey ), (jbyte *)serviceKeyBytes );
    mpw_free( &serviceKeyBytes, sizeof( *serviceKey ) );

    return serviceKey;
}

/* native String _serviceResult(final byte[] masterKey, final byte[] serviceKey, final String serviceName, final long keyCounter,
                             final int keyPurpose, @Nullable final String keyContext,
                             final int resultType, @Nullable final String resultParam, final int algorithmVersion) */
JNIEXPORT jstring JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1serviceResult(JNIEnv *env, jobject obj,
        jbyteArray masterKey, jbyteArray serviceKey, jstring serviceName, jlong keyCounter, jint keyPurpose, jstring keyContext,
        jint resultType, jstring resultParam, jint algorithmVersion) {
#error TODO
    if (!masterKey || !serviceKey || !serviceName)
        return NULL;

    jbyte *masterKeyBytes = (*env)->GetByteArrayElements( env, masterKey, NULL );
    jbyte *serviceKeyBytes = (*env)->GetByteArrayElements( env, serviceKey, NULL );
    const char *serviceNameString = (*env)->GetStringUTFChars( env, serviceName, NULL );
    const char *keyContextString = keyContext? (*env)->GetStringUTFChars( env, keyContext, NULL ): NULL;
    const char *resultParamString = resultParam? (*env)->GetStringUTFChars( env, resultParam, NULL ): NULL;
    const char *serviceResultString = mpw_service_result(
            (MPMasterKey)masterKeyBytes, serviceNameString, (MPResultType)resultType, resultParamString, (MPCounterValue)keyCounter,
            (MPKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, masterKey, masterKeyBytes, JNI_ABORT );
    (*env)->ReleaseByteArrayElements( env, serviceKey, serviceKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, serviceName, serviceNameString );
    if (keyContext)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );
    if (resultParam)
        (*env)->ReleaseStringUTFChars( env, resultParam, resultParamString );

    if (!serviceResultString)
        return NULL;

    jstring serviceResult = (*env)->NewStringUTF( env, serviceResultString );
    mpw_free_string( &serviceResultString );

    return serviceResult;
}

/* native String _serviceState(final byte[] masterKey, final byte[] serviceKey, final String serviceName, final long keyCounter,
                            final int keyPurpose, @Nullable final String keyContext,
                            final int resultType, final String resultParam, final int algorithmVersion) */
JNIEXPORT jstring JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1serviceState(JNIEnv *env, jobject obj,
        jbyteArray masterKey, jbyteArray serviceKey, jstring serviceName, jlong keyCounter, jint keyPurpose, jstring keyContext,
        jint resultType, jstring resultParam, jint algorithmVersion) {
#error TODO
    if (!masterKey || !serviceKey || !serviceName || !resultParam)
        return NULL;

    jbyte *masterKeyBytes = (*env)->GetByteArrayElements( env, masterKey, NULL );
    jbyte *serviceKeyBytes = (*env)->GetByteArrayElements( env, serviceKey, NULL );
    const char *serviceNameString = (*env)->GetStringUTFChars( env, serviceName, NULL );
    const char *keyContextString = keyContext? (*env)->GetStringUTFChars( env, keyContext, NULL ): NULL;
    const char *resultParamString = (*env)->GetStringUTFChars( env, resultParam, NULL );
    const char *serviceStateString = mpw_service_state(
            (MPMasterKey)masterKeyBytes, serviceNameString, (MPResultType)resultType, resultParamString, (MPCounterValue)keyCounter,
            (MPKeyPurpose)keyPurpose, keyContextString );
    (*env)->ReleaseByteArrayElements( env, masterKey, masterKeyBytes, JNI_ABORT );
    (*env)->ReleaseByteArrayElements( env, serviceKey, serviceKeyBytes, JNI_ABORT );
    (*env)->ReleaseStringUTFChars( env, serviceName, serviceNameString );
    if (keyContextString)
        (*env)->ReleaseStringUTFChars( env, keyContext, keyContextString );
    if (resultParam)
        (*env)->ReleaseStringUTFChars( env, resultParam, resultParamString );

    if (!serviceStateString)
        return NULL;

    jstring serviceState = (*env)->NewStringUTF( env, serviceStateString );
    mpw_free_string( &serviceStateString );

    return serviceState;
}

/* native MPIdenticon _identicon(final String fullName, final byte[] masterPassword) */
JNIEXPORT jobject JNICALL Java_com_lyndir_masterpassword_MPAlgorithm_00024Version__1identicon(JNIEnv *env, jobject obj,
        jstring fullName, jbyteArray masterPassword) {
#error TODO
    if (!fullName || !masterPassword)
        return NULL;

    const char *fullNameString = (*env)->GetStringUTFChars( env, fullName, NULL );
    jbyte *masterPasswordString = (*env)->GetByteArrayElements( env, masterPassword, NULL );

    MPIdenticon identicon = mpw_identicon( fullNameString, (char *)masterPasswordString );
    (*env)->ReleaseStringUTFChars( env, fullName, fullNameString );
    (*env)->ReleaseByteArrayElements( env, masterPassword, masterPasswordString, JNI_ABORT );
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

    return (*env)->NewObject( env, cMPIdenticon, init, fullName,
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
