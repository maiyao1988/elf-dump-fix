//
// Created by my on 18-6-5.
//

#ifndef _ELFUTILS_H
#define _ELFUTILS_H

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

//给定模糊名字，取进程maps中匹配的maps信息
void *get_map_infos(char *bufLibPath, size_t bufSize, const char *libpath);

#define RET_MEM 0
#define RET_FILE 1
//retType,决定返回dynsym等在文件中的偏移，还是在内存的偏移
void get_info_in_dynamic(size_t &dynsym, size_t &dynstr, size_t &relplt, size_t &relpltsz, size_t &loadBias, int retType, void *elf);

void *fake_dlopen(const char *libpath, int flags);

void *fake_dlsym(void *handle, const char *name);

int fake_dlclose(void *handle);

int inline_hook_check(const char *libPath);


#endif //_ELFUTILS_H
