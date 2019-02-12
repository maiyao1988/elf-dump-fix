//
// Created by my on 19-2-12.
//
#include "ElfUtils.h"
#include <stddef.h>
#include <android/log.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

static Elf_Word get_acc_flags(ElfDynInfos *infos, void *addr) {
    for (int i = 0; i < infos->nLoads; i++) {
        LoadItem *item = infos->loads + i;
        size_t saddr = (size_t)addr;
        if (saddr >= (size_t)item->addr && saddr < (size_t)(item->addr) + item->sz) {
            return item->accFlags;
        }
    }
    return 0;
}


//该函数只对地址无关代码可以使用
//地址相关代码因为重定位会修改代码段，所以无效
int inline_hook_check(const char *libPath) {
    char buf[256];

    void *load_addr = get_map_infos(buf, sizeof(buf), libPath);
    if (!load_addr) {
        return 0;
    }

    int fd = open(buf, O_RDONLY);
    struct stat st = {0};
    fstat(fd, &st);

    char *mmapBase = (char *) mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd,
                               0);
    if (!mmapBase) {
        return -1;
    }

    ElfDynInfos info2;
    get_info_in_dynamic(&info2, RET_FILE, mmapBase);

    ElfDynInfos info;
    get_info_in_dynamic(&info, RET_MEM, load_addr);


    Elf_Sym *sym = (Elf_Sym *) info.dynsym;
    char *strings = (char *) info.dynstr;

    Elf_Sym *sym2 = (Elf_Sym *)info2.dynsym;
    char *strings2 = (char *) info2.dynstr;

    //int nsym = ((size_t)dynstr-(size_t)dynsym)/sizeof(Elf_Sym);
    //仅仅适用于地址无关的so
    size_t nsym = info.relpltsz / sizeof(Elf_Rel);
    bool isHooked = false;
    for(int k = 0; k < nsym; k++, sym++, sym2++) {
        const char *symName = strings + sym->st_name;
        const char *symName2 = strings2 + sym2->st_name;
        int *addr1 = (int*)((char*)load_addr + sym->st_value - info.loadBias);
        int *addr2 = (int*)((char*)mmapBase + sym2->st_value);
        if (sym->st_value != 0 && sym2->st_value != 0) {
            //inline hook基本原理是修改函数前几个字节，这里只检测前4个字节
            Elf_Word flags = get_acc_flags(&info, addr1);
            if (flags & PF_X) {
                if (*addr1 != *addr2) {
                    isHooked = true;
                    __android_log_print(ANDROID_LOG_INFO, "fake_dlsym",
                                        "%s is hooked addrMem:%p addrFile:%08x, first 4bytes in mem:%08x, file:%08x",
                                        symName, addr1, (char *) addr2 - mmapBase, *addr1, *addr2);
                }
            }
        }
    }

    munmap(mmapBase, st.st_size);
    close(fd);
    if (isHooked) {
        return 1;
    }
    return 0;
}

