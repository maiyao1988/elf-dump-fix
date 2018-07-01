//
// Created by 麦耀 on 2018/6/30.
//
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int dumpMemory(int pid, void *begin, void *end, const char *outPath) {
    char bufMaps[256] = "/proc/self/maps";
    char bufMemPath[256] = "/proc/self/mem";

    if (pid != 0) {
        sprintf(bufMaps, "/proc/%d/maps", pid);
        sprintf(bufMemPath, "/proc/%d/mem", pid);
    }

    FILE *fMem = fopen(bufMemPath, "r");
    if (!fMem) {
        //open mem error, maybe permition deny.
        return -1;
    }

    size_t sz = (size_t)end - (size_t)begin;
    unsigned char *mem = (unsigned char*)malloc(sz);
    if (!mem) {
        return -2;
        fclose(fMem);
    }
    memset(mem, 0, sz);
    size_t off1 = (size_t)begin;

    fseek(fMem, off1, SEEK_SET);
    size_t szRead = fread(mem, 1, sz, fMem);

    size_t left = sz - szRead;
    if (left > 0) {
        printf("dump %d left", (unsigned)left);
        for (size_t i = 0; i < left; ++i) {
            unsigned char byte = 0;
            size_t szB = fread(&byte, 1, 1, fMem);
            if (szB < 1) {
                fseek(fMem, szRead+i, SEEK_SET);
                continue;
            }
            mem[szRead+i] = byte;
        }
    }
    FILE *fOut = fopen(outPath, "w");

    size_t szW = fwrite(mem, 1, sz, fOut);
    printf("%d writed\n", (unsigned)szW);
    fclose(fOut);

    free(mem);
    fclose(fMem);
    return 0;
}


