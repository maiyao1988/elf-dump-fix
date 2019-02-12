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

    size_t dynstr2 = 0, dynsym2 = 0, relplt2 = 0;
    size_t relpltsz2 = 0;
    size_t loadBias2 = 0;
    get_info_in_dynamic(dynsym2, dynstr2, relplt2, relpltsz2, loadBias2, RET_FILE, mmapBase);


    size_t dynstr = 0, dynsym = 0, relplt = 0;
    size_t relpltsz = 0;
    size_t loadBias = 0;

    get_info_in_dynamic(dynsym, dynstr, relplt, relpltsz, loadBias, RET_MEM, load_addr);


    Elf_Sym *sym = (Elf_Sym *) dynsym;
    char *strings = (char *) dynstr;

    Elf_Sym *sym2 = (Elf_Sym *)dynsym2;
    char *strings2 = (char *) dynstr2;

    //int nsym = ((size_t)dynstr-(size_t)dynsym)/sizeof(Elf_Sym);
    //仅仅适用于地址无关的so
    size_t nsym = relpltsz / sizeof(Elf_Rel);
    bool isHooked = false;
    for(int k = 0; k < nsym; k++, sym++, sym2++) {
        const char *symName = strings + sym->st_name;
        const char *symName2 = strings2 + sym2->st_name;
        int *addr1 = (int*)((char*)load_addr + sym->st_value - loadBias);
        int *addr2 = (int*)((char*)mmapBase + sym2->st_value);

        if (sym->st_value != 0 && sym2->st_value != 0) {
            if (*addr1 != *addr2) {
                isHooked = true;
                __android_log_print(ANDROID_LOG_INFO, "fake_dlsym", "%s is hooked addrMem:%p addrFile:%08x, first 4bytes in mem:%08x, file:%08x", symName, addr1, (char*)addr2-mmapBase, *addr1, *addr2);
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

