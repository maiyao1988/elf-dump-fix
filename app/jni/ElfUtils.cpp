//
// Created by my on 18-6-5.
//
#include "ElfUtils.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <android/log.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

void *get_module_addr(const char *libpath) {

    const char *tag = __FUNCTION__;
    char buff[256] = {0};
    FILE *maps = fopen("/proc/self/maps", "r");
    if(!maps)
        __android_log_print(ANDROID_LOG_ERROR, tag, "failed to open maps");
    int found = 0;
    while(fgets(buff, sizeof(buff), maps)) {
        const char *s = strstr(buff, libpath);
        if (s) {
            //just get the first line, which includes the base address.
            found = 1;
            break;
        }
    }
    fclose(maps);

    if(!found) {
        __android_log_print(ANDROID_LOG_ERROR, tag, "%s not found in my userspace", libpath);
        return 0;
    }

    void *load_addr = 0;
    if(sscanf(buff, "%p", &load_addr) != 1) {
        __android_log_print(ANDROID_LOG_ERROR, tag, "failed to read load address for %s", libpath);
        return 0;
    }

    __android_log_print(ANDROID_LOG_INFO, tag, "%s loaded in Android at %p", libpath, load_addr);

    return load_addr;
}

void get_info_in_dynamic(Elf_Ehdr *elf, size_t &dynsym, size_t &dynstr, size_t &relplt, size_t &relpltsz, size_t &loadBias) {
    const char *elfBase = (const char*)elf;
    //locate elf with phdr.not shdr.
    Elf_Phdr *phdr = (Elf_Phdr*)(elfBase + elf->e_phoff);
    int phNum = elf->e_phnum;
    size_t dyn_size = 0, dyn_off = 0;
    Elf_Addr minLoadAddr = (Elf_Addr)-1;
    for (int i = 0; i < phNum; ++i) {
        Elf_Word p_type = phdr[i].p_type;
        if (p_type == PT_DYNAMIC) {
            //get dyn symbol table from dynamic section
            dyn_size = phdr[i].p_memsz;
            dyn_off = phdr[i].p_vaddr;
        }
        else if (p_type == PT_LOAD) {
            Elf_Addr loadAddr = phdr[i].p_vaddr;
            if (minLoadAddr > loadAddr) {
                minLoadAddr = loadAddr;
            }
        }
    }
    dyn_off -= minLoadAddr;

    const Elf_Dyn* dyn = (const Elf_Dyn*)(elfBase+dyn_off);
    size_t n = dyn_size / sizeof(Elf_Dyn);
    for (int i = 0; i < n; ++i) {
        int type = (int)dyn[i].d_tag;
        switch (type) {
            case DT_SYMTAB:
                dynsym =  dyn[i].d_un.d_ptr - minLoadAddr;
                break;
            case DT_STRTAB:
                dynstr =  dyn[i].d_un.d_ptr - minLoadAddr;
                break;
            case DT_JMPREL:
                relplt =  dyn[i].d_un.d_ptr - minLoadAddr;
                break;
            case DT_PLTRELSZ:
                relpltsz = dyn[i].d_un.d_val;
                break;
            default:
                break;
        }
    }
    loadBias = minLoadAddr;
}
