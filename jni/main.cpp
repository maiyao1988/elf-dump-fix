//
// Created by 麦耀 on 2018/7/1.
//
#include <stdio.h>
#include <unistd.h>
#include "fix.h"

int dumpMemory(int pid, void *begin, void *end, const char *outPath);

static int __main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("%s <pid> <base_hex> <end_hex> <outPath>\n", argv[0]);
        return -1;
    }

    int pid = strtol(argv[1], 0, 10);
    void *begin = 0, *end = 0;
    sscanf(argv[2], "%p", &begin);
    sscanf(argv[3], "%p", &end);
    const char *outPath = argv[4];
    char tmpPath[255] = {0};
    sprintf(tmpPath, "%s.tmp", outPath);

    if (pid != 0) {
        printf("stop process %d before dump\n", pid);
        kill(pid, SIGSTOP);
    }
    dumpMemory(pid, begin, end, tmpPath);
    if (pid != 0) {
        printf("resume process %d after dump\n", pid);
        kill(pid, SIGCONT);
    }
    fix_so(tmpPath, outPath, begin);
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

    int argc=5;
    char *argv[] = {"dump", "0", "0xb4509000", "0xb47fe000", "/sdcard/libart_fix.so"};
    __main(argc, argv);

    result = JNI_VERSION_1_4;

    return result;
}

