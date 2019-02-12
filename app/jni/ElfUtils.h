//
// Created by my on 18-6-5.
//

#ifndef DXSTUB_ELFUTILS_H
#define DXSTUB_ELFUTILS_H

#include <stdint.h>
#include <elf.h>

#ifdef __aarch64__
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Rela Elf_Rel;
typedef Elf64_Shdr Elf_Shdr;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Shdr Elf_Shdr;
#endif

void *get_module_addr(const char *libpath);

void get_info_in_dynamic(Elf_Ehdr *elf, size_t &dynsym, size_t &dynstr, size_t &relplt, size_t &relpltsz, size_t &loadBias);

void *fake_dlopen(const char *libpath, int flags);

void *fake_dlsym(void *handle, const char *name);

int fake_dlclose(void *handle);


#endif //DXSTUB_ELFUTILS_H
