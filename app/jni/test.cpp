//
// Created by my on 20-2-27.
//

#include <jni.h>

int main(int argc, char *argv[]);
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = 0;
    jint result = -1;

    if (vm->GetEnv((void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }

    //0xb4509000 0xb47fe000

    int argc=5;
    char *argv[] = {"dump", "0", "0xb4509000", "0xb47fe000", "/sdcard/libart_fix.so"};
    main(argc, argv);

    result = JNI_VERSION_1_4;

    return result;
}


