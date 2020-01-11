//
// Created by 麦耀 on 2018/7/1.
//
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "fix.h"

int dumpMemory(int pid, uint64_t begin, uint64_t end, const char *outPath);

static const char *_sandardlizeAddrs(char *buf, const char *addr) {
    if (addr[0] != '0' || addr[1] != 'x') {
        sprintf(buf, "0x%s", addr);
        return buf;
    }
    else{
        return addr;
    }
}

static int __main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("%s <pid> <base_hex> <end_hex> <outPath> [is-stop-process-before-dump] [is-fix-so-after-dump]\n", argv[0]);
        return -1;
    }

    long pid = strtol(argv[1], 0, 10);
    uint64_t begin = 0, end = 0;
    char bufBegin[255] = {0};
    const char *strBegin = _sandardlizeAddrs(bufBegin, argv[2]);

    begin = strtoull(strBegin, 0, 16);

    char bufEnd[255] = {0};
    const char *strEnd = _sandardlizeAddrs(bufEnd, argv[3]);

    end = strtoull(strEnd, 0, 16);

    const char *outPath = argv[4];
    char tmpPath[255] = {0};
    sprintf(tmpPath, "%s.tmp", outPath);

    bool stopBeforeDump = false;
    if (argc > 5) {
        stopBeforeDump = argv[5][0] != '0';
    }
    if (pid != 0 && stopBeforeDump) {
        printf("stop process %ld before dump\n", pid);
        kill(pid, SIGSTOP);
    }
    int res = dumpMemory(pid, begin, end, tmpPath);
    if (res < 0) {
        printf("error dumpMemory return %d, did you run in root, did pid exist?\n", res);
        return res;
    }
    if (pid != 0 && stopBeforeDump) {
        printf("resume process %ld after dump\n", pid);
        kill(pid, SIGCONT);
    }
    chmod(tmpPath, 0666);
    bool isFixSo = true;
    if (argc > 6) {
        isFixSo = argv[6][0] != '0';
    }

    if (isFixSo) {
        printf("try fix %s\n", tmpPath);
        fix_so(tmpPath, outPath, (unsigned) begin);
        printf("end fix %s output to %s\n", tmpPath, outPath);
        chmod(outPath, 0666);
    }
    else {
        rename(tmpPath, outPath);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    return __main(argc, argv);
}

#include <jni.h>
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
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

