//
//  main_fix.cpp
//  elffix
//
//  Created by 麦耀 on 2018/7/1.
//  Copyright © 2018年 maiyao. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <errno.h>
#include "app/jni/ElfFixSection/fix.h"

int main(int argc, char *argv[]) {
    /*
    void *p1 = mmap((void*)0x40000000, 0x2000, PROT_NONE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    void *p3 = mmap((void*)0x40003000, 0x1000, PROT_READ, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    void *p2 = mmap((void*)0x40000000-0x1000, 0x5000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    const char *s = strerror(errno);
     */
    if (argc < 4) {
        printf("<src_so_path> <base_addr_in_memory_in_hex> <out_so_path>\n");
        return -1;
    }
    const char *openPath = argv[1];
    uint64_t base = strtoull(argv[2], 0, 16);
    const char *outPutPath = argv[3];
    fix_so(openPath, outPutPath, base);
    
}
