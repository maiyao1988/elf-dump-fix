//
//  main_fix.cpp
//  elffix
//
//  Created by 麦耀 on 2018/7/1.
//  Copyright © 2018年 maiyao. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include "jni/fix.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("<src_so_path> [base_addr_in_memory_in_hex] [<out_so_path>]\n");
        return -1;
    }
    const char *openPath = argv[1];
    const char *outPutPath = "fix.so";
    unsigned base = 0;
    if (argc > 2)
    {
        base = strtoul(argv[2], 0, 16);
        outPutPath = argv[2];
    }
    
    if (argc > 3)
    {
        outPutPath = argv[3];
    }
    fix_so(openPath, outPutPath, base);
    
    
}
