//
// Created by my on 18-6-4.
//


#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <android/log.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include "ElfUtils.h"

/*
void *got_hook(const char *moduleName, const char *target_name, void *callback){
    soinfo *si = (soinfo *)dlopen(moduleName, RTLD_NOW | RTLD_LOCAL);

    void *addrLoad = get_map_infos(0, 0. moduleName);
    if (!addrLoad) {
        return 0;
    }

    ElfDynInfos info;
    get_info_in_dynamic(&info, RET_MEM, load_addr);

    size_t count = info.relpltsz / sizeof(Elf_Rel);

    Elf_Rel *rel = (Elf_Rel*)((size_t)info.relplt);

    Elf_Sym *symtab = (Elf_Sym*)((size_t)info.dynsym);
    const char *strings = (const char *) ((size_t)info.dynstr);

    void *oldFunAddr = 0;
    for (size_t idx = 0; idx<count; ++idx, ++rel) {
        unsigned type = (unsigned)ELF_R_TYPE(rel->r_info);
        unsigned sym = (unsigned)ELF_R_SYM(rel->r_info);

        Elf_Addr addrBias2Load = rel->r_offset - loadBias;
        Elf_Addr addrInGot = (Elf_Addr)(addrBias2Load + (uintptr_t)addrLoad);

        if (type == 0) {
            continue;
        }

        if (sym != 0) {
            const char *sym_name = strings + symtab[sym].st_name;


            if (strcmp(sym_name, target_name) != 0)
                continue;

            LOGI("%d sym_name=%s, addrInGot=%p", idx, sym_name, addrInGot);

            oldFunAddr = *(void**)addrInGot;

            if (callback != NULL) {
                Elf_Addr seg_page_start = PAGE_START(addrInGot);
                Elf_Addr seg_page_end = PAGE_END(addrInGot + 4);
                errno = 0;

                int r = mprotect((void*)seg_page_start, seg_page_end - seg_page_start, PROT_READ | PROT_WRITE);

                *(void**)addrInGot = callback;
            }
            break;
        }
    }

    return oldFunAddr;
}
*/

struct FakeHandle{
    size_t load_addr;
    void *dynstr;
    void *dynsym;
    size_t nsym;
    size_t loadBias;
};

void *fake_dlopen(const char *libpath, int flags)
{
    const char *tag = "fake_dlopen";

    void *load_addr = get_map_infos(0, 0, libpath);
    if (!load_addr) {
        return 0;
    }

    FakeHandle *ctx = (FakeHandle *) calloc(1, sizeof(FakeHandle));
    ctx->load_addr = (size_t)load_addr;

    ElfDynInfos info;
    get_info_in_dynamic(&info, RET_MEM, load_addr);

    ctx->dynsym = (void*)(info.dynsym);
    ctx->dynstr = (void*)(info.dynstr);
    ctx->loadBias = info.loadBias;

    if(!ctx->dynstr || !ctx->dynsym) {
        __android_log_print(ANDROID_LOG_ERROR, tag, "dynamic sections not found in %s", libpath);
        return 0;
    }

    ctx->nsym = ((size_t)ctx->dynstr-(size_t)ctx->dynsym)/sizeof(Elf_Sym);
    return ctx;
}

void *fake_dlsym(void *handle, const char *name)
{
    FakeHandle *ctx = (FakeHandle*) handle;
    Elf_Sym *sym = (Elf_Sym *) ctx->dynsym;
    char *strings = (char *) ctx->dynstr;

    for(int k = 0; k < ctx->nsym; k++, sym++) {
        const char *symName = strings + sym->st_name;
        if (strcmp(symName, name) == 0) {
            void *ret = (char*)ctx->load_addr + sym->st_value - ctx->loadBias;
            __android_log_print(ANDROID_LOG_INFO, "fake_dlsym", "%s found at %p", name, ret);
            return ret;
        }
    }
    return 0;
}

int fake_dlclose(void *handle) {
    free(handle);
    return 0;
}


