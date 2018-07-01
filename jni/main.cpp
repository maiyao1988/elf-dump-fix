//
// Created by 麦耀 on 2018/7/1.
//
#include <stdio.h>
#include "fix.h"

int dumpMemory(int pid, void *begin, void *end, const char *outPath);

static int __main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("%s <pid> <base_hex> <end_hex> <outPath>", argv[0]);
    }

    int pid = strtol(argv[1], 0, 10);
    void *p1 = 0, *p2 = 0;
    sscanf(argv[2], "%p", &p1);
    sscanf(argv[3], "%p", &p2);
    const char *outPath = argv[4];
    char tmpPath[255] = {0};
    sprintf(tmpPath, "%s.tmp", outPath);
    dumpMemory(pid, p1, p2, tmpPath);
    fix_so(tmpPath, outPath, 0);
    return 0;
}

int main(int argc, char *argv[]) {
    return __main(argc, argv);
}

#include <jni.h>
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    jint result = -1;

    if (vm->GetEnv((void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }

    //0xb4509000 0xb47fe000
    /*
    const char *soPath = "/sdcard/libart1.so";
    dumpMemory(0, (void*)0xb4509000 , (void*)0xb47fe000, soPath);

    const char *soFixPath = "/sdcard/libart_fix.so";

    fix_so(soPath, soFixPath, 0);
     */
    /* success -- return valid version number */

    int argc=5;
    char *argv[] = {"dump", "0", "0xb4509000", "0xb47fe000", "/sdcard/libart_fix.so"};
    __main(argc, argv);

    result = JNI_VERSION_1_4;

    return result;
}


