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
#include <sys/exec_elf.h>

void *get_map_infos(char *bufLibFullPath, size_t sz, const char *libpath) {
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
    char libPath[300] = {0};
    //ea116000-ea117000 r--p 0000f000 fd:00 3638                               /system/lib/libcutils.so
    if(sscanf(buff, "%p-%*p %*c%*c%*c%*c %*x %*x:%*x %*d %s", &load_addr, libPath) != 2) {
        __android_log_print(ANDROID_LOG_ERROR, tag, "failed to read load address for %s", libpath);
        return 0;
    }

    if (bufLibFullPath) {
        strncpy(bufLibFullPath, libPath, sz);
    }

    __android_log_print(ANDROID_LOG_INFO, tag, "%s loaded in Android at %p", libpath, load_addr);

    return load_addr;
}

void get_info_in_dynamic(ElfDynInfos *infos, int retType, void *elf) {
    memset(infos, 0, sizeof(ElfDynInfos));
    const char *elfBase = (const char*)elf;
    Elf_Ehdr *ehdr = (Elf_Ehdr*)elf;
    //locate elf with phdr.not shdr.
    Elf_Phdr *phdr = (Elf_Phdr*)(elfBase + ehdr->e_phoff);
    int phNum = ehdr->e_phnum;
    size_t dyn_size = 0, dyn_off = 0;
    //由于libart第一个load vaddr不是0,系统装载的时候当0装载，所以所有相对于loadAddr的mem地址都需要减去第一个load的vaddr
    Elf_Addr minLoadAddr = (Elf_Addr)-1;
    //内存与文件中的偏移
    Elf_Addr biasMemFile = 0;
    unsigned int nLoads = 0;
    for (int i = 0; i < phNum; ++i) {
        Elf_Word p_type = phdr[i].p_type;
        if (p_type == PT_DYNAMIC) {
            if (retType == RET_MEM) {
                //get dyn symbol table from dynamic section
                dyn_size = phdr[i].p_memsz;
                dyn_off = phdr[i].p_vaddr;
            }
            else if (retType == RET_FILE){
                dyn_size = phdr[i].p_filesz;
                dyn_off = phdr[i].p_offset;
            }
        }
        else if (p_type == PT_LOAD) {
            if (retType == RET_MEM) {
                //只有找内存中的偏移和大小才需要考虑这个问题
                Elf_Addr loadAddr = phdr[i].p_vaddr;
                if (minLoadAddr > loadAddr) {
                    minLoadAddr = loadAddr;
                }
            }

            if (nLoads == 0) {
                biasMemFile = phdr[i].p_vaddr - phdr[i].p_offset;
            }
            if (nLoads < MAX_LOAD_ITEM) {
                LoadItem *item = &(infos->loads[nLoads]);
                item->accFlags = phdr[i].p_flags;
                if (retType == RET_MEM) {
                    item->addr = (void *) (phdr[i].p_vaddr + elfBase);
                    item->sz = phdr[i].p_memsz;
                } else {
                    item->addr = (void *) (phdr[i].p_offset + elfBase);
                    item->sz = phdr[i].p_filesz;
                }
                nLoads++;
            }
        }
        infos->nLoads = nLoads;
    }

    if (retType == RET_MEM) {
        for (unsigned int i = 0; i < nLoads; i++) {
            infos->loads[i].addr = (void*)((size_t )infos->loads[i].addr - minLoadAddr);
        }
        dyn_off -= minLoadAddr;
    }

    size_t bias = 0;
    if (retType == RET_MEM) {
        bias = minLoadAddr;
    }
    else if (retType == RET_FILE) {
        bias = biasMemFile;
    }

    //由于在dynamic的地址全部都是内存中的偏移，有dynamic的地址全部在第一个load里面, 以需要找到文件中的对应位置的话，
    //需要减去第一个load的vaddr与offset的偏移
    const Elf_Dyn* dyn = (const Elf_Dyn*)(elfBase+dyn_off);
    size_t n = dyn_size / sizeof(Elf_Dyn);
    for (int i = 0; i < n; ++i) {
        int type = (int)dyn[i].d_tag;
        const Elf_Dyn *dynNow = dyn + i;
        switch (type) {
            case DT_SYMTAB:
                infos->dynsym =  (void*)(dynNow->d_un.d_ptr - bias + (size_t)elfBase);
                break;
            case DT_STRTAB:
                infos->dynstr =  (void*)(dynNow->d_un.d_ptr - bias + (size_t)elfBase);
                break;
            case DT_JMPREL:
                infos->relplt =  (void*)(dynNow->d_un.d_ptr - bias + (size_t)elfBase);
                break;
            case DT_PLTRELSZ:
                infos->relpltsz = dynNow->d_un.d_val;
                break;
            default:
                break;
        }
    }
    infos->loadBias = bias;
}
