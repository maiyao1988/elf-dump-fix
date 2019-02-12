#include "Substrate/SubstrateHook.h"

#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <unistd.h>
#include <android/log.h>
#include "StackDump.h"
#include "ElfUtils.h"

#define TAG "REV-DEMO"

typedef ssize_t (*fnread) (int fd, void *buf, size_t count);
fnread ori_read = read;

ssize_t my_read(int fd, void *buf, size_t count) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "read call fd=%d, buf=%p, count=%u", fd, buf, count);
    DUMP_CALL_STACK(TAG);
    return ori_read(fd, buf, count);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_reverse_my_reverseutils_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {


    __android_log_print(ANDROID_LOG_INFO, TAG, "before hook %p", ori_read);
    MSHookFunction((void*)read, (void*)my_read, (void**)&ori_read);
    __android_log_print(ANDROID_LOG_INFO, TAG, "after hook %p", ori_read);

    inline_hook_check("libc.so");
    inline_hook_check("libart.so");

    void *p = fake_dlopen("libc.so", 0);
    fnread f = (fnread ) fake_dlsym(p, "read");
    fake_dlclose(p);

    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
