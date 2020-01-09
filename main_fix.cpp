//
//  main_fix.cpp
//  elffix
//
//  Created by 麦耀 on 2018/7/1.
//  Copyright © 2018年 maiyao. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include "app/jni/ElfFixSection/fix.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("<src_so_path> <base_addr_in_memory_in_hex> <out_so_path>\n");
        return -1;
    }
    const char *openPath = argv[1];
    unsigned long long base = strtoull(argv[2], 0, 16);
    const char *outPutPath = argv[3];
    fix_so(openPath, outPutPath, base);
    
}
