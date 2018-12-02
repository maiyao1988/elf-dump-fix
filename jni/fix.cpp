#define _CRT_SECURE_NO_WARNINGS
#include "fix.h"

static const char* g_str = "..dynsym..dynstr..hash..rel.dyn..rel.plt..plt..text@.ARM.extab..ARM.exidx..fini_array..init_array..dynamic..got..data..bss..shstrtab\0";
static const char* g_strtabcontent = "\0.dynsym\0.dynstr\0.hash\0.rel.dyn\0.rel.plt\0.plt\0.text@.ARM.extab\0.ARM.exidx\0.fini_array\0.init_array\0.dynamic\0.got\0.data\0.bss\0.shstrtab\0";

static Elf32_Word _get_off_in_shstrtab(const char *name)
{
	return (Elf32_Word)(strstr(g_str, name) - g_str);
}

//段表
static Elf32_Shdr g_shdr[SHDRS] = { 0 };

static void _get_elf_header(Elf32_Ehdr *pehdr, const char *buffer)
{
	int header_len = sizeof(Elf32_Ehdr);
	memcpy(pehdr, (void*)buffer, header_len);
}

static long _get_file_len(FILE *p)
{
	fseek (p, 0, SEEK_END);
	long fsize = ftell (p);
	rewind (p);
	return fsize;
}

static void _fix_relative_rebase(const char *buffer, size_t bufSize, Elf32_Word imageBase)
{
    Elf32_Addr addr = g_shdr[RELDYN].sh_addr;
    size_t sz = g_shdr[RELDYN].sh_size;
    size_t n = sz / sizeof(Elf32_Rel);
    Elf32_Rel *rel = (Elf32_Rel*)(buffer+addr);
    const char *border = buffer+bufSize;
    for (size_t i = 0; i < n; ++i,++rel)
    {
        int type = ELF32_R_TYPE(rel->r_info);
        //unsigned sym = (unsigned)ELF32_R_SYM(rel->r_info);
        if (type == R_ARM_RELATIVE)
        {
            Elf32_Addr off = rel->r_offset;
            unsigned *offIntBuf = (unsigned*)(buffer+off);
            if (border < (const char*)offIntBuf) {
                printf("relocation off %x invalid, out of border...", off);
            }
            unsigned addrNow = *offIntBuf;
            addrNow -= imageBase;
            (*offIntBuf) = addrNow;
        }
    }
}

static void _regen_section_header(const Elf32_Ehdr *pehdr, const char *buffer)
{
	Elf32_Phdr load = { 0 };
	Elf32_Phdr *phdr = (Elf32_Phdr*)(buffer + pehdr->e_phoff);
	int ph_num = pehdr->e_phnum;
	int dyn_size = 0, dyn_off = 0;
	int loadIndex = 0;
	//TODO:所有相对于module base的地址都要减去这个地址
    size_t minLoad = 0;
	for(int i = 0;i < ph_num;i++) {
        if (phdr[i].p_type == PT_LOAD) {
			if (minLoad > phdr[i].p_vaddr) {
				minLoad = phdr[i].p_vaddr;
			}
		}
	}
	for(int i = 0;i < ph_num;i++) {
		//段在文件中的偏移修正，因为从内存dump出来的文件偏移就是在内存的偏移
		phdr[i].p_offset =  phdr[i].p_vaddr;
		Elf32_Word p_type = phdr[i].p_type;
		if (phdr[i].p_type == PT_LOAD) {
			loadIndex++;
			if (phdr[i].p_vaddr > 0x0 && loadIndex == 2) {
				//BSS一般都在第二个load节的最后
				load = phdr[i];
				g_shdr[BSS].sh_name = _get_off_in_shstrtab(".bss");
				//BSS大小无所谓
				g_shdr[BSS].sh_type = SHT_NOBITS;
				g_shdr[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
				g_shdr[BSS].sh_addr =  phdr[i].p_vaddr - minLoad + phdr[i].p_filesz;
				//因为bss段映射到到load节的最后，加上so里面文件大小与内存映射大小不一致的基本只有bss，所以内存多出来的内容基本就是bss段的大小。
				g_shdr[BSS].sh_size = phdr[i].p_memsz - phdr[i].p_filesz;
				g_shdr[BSS].sh_offset = g_shdr[BSS].sh_addr;
				g_shdr[BSS].sh_addralign = 4;
			}
		}
		else if(p_type == PT_DYNAMIC) {
			//动态表，动态表包括很多项，找到动态表位置可以恢复大部分结构,这个是恢复的突破口
			g_shdr[DYNAMIC].sh_name = _get_off_in_shstrtab(".dynamic");
			g_shdr[DYNAMIC].sh_type = SHT_DYNAMIC;
			g_shdr[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
			g_shdr[DYNAMIC].sh_addr = phdr[i].p_vaddr - minLoad;
			g_shdr[DYNAMIC].sh_offset = phdr[i].p_vaddr - minLoad;
			g_shdr[DYNAMIC].sh_size = phdr[i].p_filesz;
			g_shdr[DYNAMIC].sh_link = 2;
			g_shdr[DYNAMIC].sh_info = 0;
			g_shdr[DYNAMIC].sh_addralign = 4;
			g_shdr[DYNAMIC].sh_entsize = 8;
			dyn_size = phdr[i].p_memsz;
			dyn_off = phdr[i].p_vaddr-minLoad;
		}
		
		else if(phdr[i].p_type == PT_LOPROC || phdr[i].p_type == PT_LOPROC + 1) {
			g_shdr[ARMEXIDX].sh_name = _get_off_in_shstrtab(".ARM.exidx");
			g_shdr[ARMEXIDX].sh_type = SHT_LOPROC;
			g_shdr[ARMEXIDX].sh_flags = SHF_ALLOC;
			g_shdr[ARMEXIDX].sh_addr = phdr[i].p_vaddr;
			g_shdr[ARMEXIDX].sh_offset = phdr[i].p_vaddr;
			g_shdr[ARMEXIDX].sh_size = phdr[i].p_memsz;
			g_shdr[ARMEXIDX].sh_link = 7;
			g_shdr[ARMEXIDX].sh_info = 0;
			g_shdr[ARMEXIDX].sh_addralign = 4;
			g_shdr[ARMEXIDX].sh_entsize = 8;
		}
	}
	
	const Elf32_Dyn* dyn = (const Elf32_Dyn*)(buffer+dyn_off);
	int n = dyn_size / sizeof(Elf32_Dyn);
	
	Elf32_Word __global_offset_table = 0;
	for (int i=0; i < n; i++) {
		int tag = dyn[i].d_tag;
		switch (tag) {
			case DT_SYMTAB:
				g_shdr[DYNSYM].sh_name = _get_off_in_shstrtab(".dynsym");
				g_shdr[DYNSYM].sh_type = SHT_DYNSYM;
				g_shdr[DYNSYM].sh_flags = SHF_ALLOC;
				g_shdr[DYNSYM].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[DYNSYM].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[DYNSYM].sh_link = 2;
				g_shdr[DYNSYM].sh_info = 1;
				g_shdr[DYNSYM].sh_addralign = 4;
				g_shdr[DYNSYM].sh_entsize = 16;
				break;
				
			case DT_STRTAB:
				g_shdr[DYNSTR].sh_name = _get_off_in_shstrtab(".dynstr");
				g_shdr[DYNSTR].sh_type = SHT_STRTAB;
				g_shdr[DYNSTR].sh_flags = SHF_ALLOC;
				g_shdr[DYNSTR].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[DYNSTR].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[DYNSTR].sh_addralign = 1;
				g_shdr[DYNSTR].sh_entsize = 0;
				break;
				
			case DT_STRSZ:
				g_shdr[DYNSTR].sh_size = dyn[i].d_un.d_val;
				break;
				
			case DT_HASH:
			{
				int nbucket = 0, nchain = 0;
				g_shdr[HASH].sh_name = _get_off_in_shstrtab(".hash");
				g_shdr[HASH].sh_type = SHT_HASH;
				g_shdr[HASH].sh_flags = SHF_ALLOC;
				g_shdr[HASH].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[HASH].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				memcpy(&nbucket, buffer + g_shdr[HASH].sh_offset, 4);
				memcpy(&nchain, buffer + g_shdr[HASH].sh_offset + 4, 4);
				g_shdr[HASH].sh_size = (nbucket + nchain + 2) * sizeof(int);
				g_shdr[HASH].sh_link = 4;
				g_shdr[HASH].sh_info = 1;
				g_shdr[HASH].sh_addralign = 4;
				g_shdr[HASH].sh_entsize = 4;
				break;
			}
			case DT_REL:
				g_shdr[RELDYN].sh_name = _get_off_in_shstrtab(".rel.dyn");
				g_shdr[RELDYN].sh_type = SHT_REL;
				g_shdr[RELDYN].sh_flags = SHF_ALLOC;
				g_shdr[RELDYN].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[RELDYN].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[RELDYN].sh_link = 4;
				g_shdr[RELDYN].sh_info = 0;
				g_shdr[RELDYN].sh_addralign = 4;
				g_shdr[RELDYN].sh_entsize = 8;
				break;
				
			case DT_RELSZ:
				g_shdr[RELDYN].sh_size = dyn[i].d_un.d_val;
				break;
				
			case DT_JMPREL:
				g_shdr[RELPLT].sh_name = _get_off_in_shstrtab(".rel.plt");
				g_shdr[RELPLT].sh_type = SHT_REL;
				g_shdr[RELPLT].sh_flags = SHF_ALLOC;
				g_shdr[RELPLT].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[RELPLT].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[RELPLT].sh_link = 1;
				g_shdr[RELPLT].sh_info = 6;
				g_shdr[RELPLT].sh_addralign = 4;
				g_shdr[RELPLT].sh_entsize = 8;
				break;
				
			case DT_PLTRELSZ:
				g_shdr[RELPLT].sh_size = dyn[i].d_un.d_val;
				break;
				
			case DT_FINI_ARRAY:
				g_shdr[FINIARRAY].sh_name = _get_off_in_shstrtab(".fini_array");
				g_shdr[FINIARRAY].sh_type = 15;
				g_shdr[FINIARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
				g_shdr[FINIARRAY].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[FINIARRAY].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[FINIARRAY].sh_addralign = 4;
				g_shdr[FINIARRAY].sh_entsize = 0;
				break;
				
			case DT_FINI_ARRAYSZ:
				g_shdr[FINIARRAY].sh_size = dyn[i].d_un.d_ptr;
				break;
				
			case DT_INIT_ARRAY:
				g_shdr[INITARRAY].sh_name = _get_off_in_shstrtab(".init_array");
				g_shdr[INITARRAY].sh_type = 14;
				g_shdr[INITARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
				g_shdr[INITARRAY].sh_offset = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[INITARRAY].sh_addr = dyn[i].d_un.d_ptr - minLoad;
				g_shdr[INITARRAY].sh_addralign = 4;
				g_shdr[INITARRAY].sh_entsize = 0;
				break;
				
			case DT_INIT_ARRAYSZ:
				g_shdr[INITARRAY].sh_size = dyn[i].d_un.d_ptr - minLoad;
				break;
				
			case DT_PLTGOT:
				__global_offset_table = dyn[i].d_un.d_ptr;
				g_shdr[GOT].sh_name = _get_off_in_shstrtab(".got");
				g_shdr[GOT].sh_type = SHT_PROGBITS;
				g_shdr[GOT].sh_flags = SHF_WRITE | SHF_ALLOC;
				//TODO:这里基于假设.got一定在.dynamic段之后，并不可靠，王者荣耀libGameCore.so就是例外
				g_shdr[GOT].sh_addr = g_shdr[DYNAMIC].sh_addr + g_shdr[DYNAMIC].sh_size;
				g_shdr[GOT].sh_offset = g_shdr[GOT].sh_addr;
				g_shdr[GOT].sh_addralign = 4;
				break;
			case DT_INIT:
				//找到init段代码，但是无法知道有多长，只好做一个警告，提醒使用者init段存在，脱壳代码可能存在这里
				printf("warning .init exist at 0x%08x\n", dyn[i].d_un.d_ptr);
				break;
			case DT_TEXTREL:
				//地址相关的so，警告，暂时不做处理
				printf("warning DT_TEXTREL found, so is address depend.\n");
				break;
		}
	}
	if (__global_offset_table)
	{
		Elf32_Word gotBase = g_shdr[GOT].sh_addr;
		unsigned nRelPlt = g_shdr[RELPLT].sh_size / sizeof(Elf32_Rel);
		
		//__global_offset_table里面成员个数等于RELPLT的成员数+3个固定成员
		Elf32_Word gotEnd = __global_offset_table + 4 * (nRelPlt + 3);
		
		//上面那种方式计算不可靠，根据libGameCore.so分析，nRelPlt比数量比实际GOT数量多10个，暂时没发现这十个成员的特殊性
		//.got的结尾就是.data的开始，根据经验，data的地址总是与0x1000对齐。以此来修正地址
	 	gotEnd = gotEnd & ~0x0FFF;
		
		g_shdr[DATA].sh_name = _get_off_in_shstrtab(".data");
		g_shdr[DATA].sh_type = SHT_PROGBITS;
		g_shdr[DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
		g_shdr[DATA].sh_addr = gotEnd;
		g_shdr[DATA].sh_offset = g_shdr[DATA].sh_addr;
		g_shdr[DATA].sh_size = load.p_vaddr + load.p_filesz - g_shdr[DATA].sh_addr;
		g_shdr[DATA].sh_addralign = 4;
		if (gotEnd > gotBase)
		{
			g_shdr[GOT].sh_size = gotEnd - gotBase;
		}
		else
		{
			//.got紧接着.dynamic的假设不成立
			//虽然算不准got段的真正的地址，但是可以用__global_offset_table的地址充当.got段的地址，__global_offset_table以上的地址全部为
			//数据段的修正地址，对分析关系不大。
			printf("warning .got is not after .dynamic use __global_offset_table as .got base\n");
			g_shdr[GOT].sh_addr = g_shdr[GOT].sh_offset = __global_offset_table;
			g_shdr[GOT].sh_size = gotEnd - __global_offset_table;
		}
	}
	
	//STRTAB地址 - SYMTAB地址 = SYMTAB大小
	g_shdr[DYNSYM].sh_size = g_shdr[DYNSTR].sh_addr - g_shdr[DYNSYM].sh_addr;
	
	g_shdr[PLT].sh_name = _get_off_in_shstrtab(".plt");
	g_shdr[PLT].sh_type = SHT_PROGBITS;
	g_shdr[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	g_shdr[PLT].sh_addr = g_shdr[RELPLT].sh_addr + g_shdr[RELPLT].sh_size;
	g_shdr[PLT].sh_offset = g_shdr[PLT].sh_addr;
	g_shdr[PLT].sh_size = (20 + 12 * (g_shdr[RELPLT].sh_size) / sizeof(Elf32_Rel));
	g_shdr[PLT].sh_addralign = 4;
	
	g_shdr[TEXT].sh_name = _get_off_in_shstrtab(".text");
	g_shdr[TEXT].sh_type = SHT_PROGBITS;
	g_shdr[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	g_shdr[TEXT].sh_addr = g_shdr[PLT].sh_addr + g_shdr[PLT].sh_size;
	g_shdr[TEXT].sh_offset = g_shdr[TEXT].sh_addr;
	g_shdr[TEXT].sh_size = g_shdr[ARMEXIDX].sh_addr - g_shdr[TEXT].sh_addr;
	
	g_shdr[STRTAB].sh_name = _get_off_in_shstrtab(".shstrtab");
	g_shdr[STRTAB].sh_type = SHT_STRTAB;
	g_shdr[STRTAB].sh_flags = SHT_NULL;
	g_shdr[STRTAB].sh_addr = 0;	//写文件的时候修正
	g_shdr[STRTAB].sh_size = (Elf32_Word)strlen(g_str) + 1;
	g_shdr[STRTAB].sh_addralign = 1;
}

int fix_so(const char *openPath, const char *outPutPath, unsigned ptrbase)
{
	FILE *fr = NULL, *fw = NULL;
	char *buffer = NULL;

	Elf32_Word base = (Elf32_Word)ptrbase;

	fr = fopen(openPath,"rb");
	
	if(fr == NULL) {
		printf("Open failed: \n");
        return -3;
	}
    char buf[4] = {0};
    fread(buf, 1, 4, fr);
    if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        printf("error header is not .ELF!!!");
		return -4;
    }
	fseek(fr, 0, SEEK_SET);
	
	size_t flen = _get_file_len(fr);
	
	buffer = (char*)malloc(flen);
	if (buffer == NULL) {
		printf("Malloc error\n");
		fclose(fr);
        return -1;
	}
	
	unsigned long result = fread (buffer, 1, flen, fr);
	if (result != flen) {
		printf("Reading %s error\n", openPath);
        fclose(fr);
		free(buffer);
		return -2;
	}
	fw = fopen(outPutPath, "wb");
	if(fw == NULL) {
		printf("Open failed: %s\n", outPutPath);
		fclose(fr);
		free(buffer);
		return -4;
	}
	
	Elf32_Ehdr ehdr = {0};
	_get_elf_header(&ehdr, buffer);

	_regen_section_header(&ehdr, buffer);
    
    _fix_relative_rebase(buffer, flen, ptrbase);
	
	size_t shstrtabsz = strlen(g_str)+1;
	if (base)
		ehdr.e_entry = base;
	ehdr.e_shnum = SHDRS;
	//倒数第一个为段名字符串段
	ehdr.e_shstrndx = SHDRS - 1;
	ehdr.e_shentsize = sizeof(Elf32_Shdr);
	
	//段表头紧接住段表最后一个成员--字符串段之后
	ehdr.e_shoff = (Elf32_Off)(flen + shstrtabsz);
	
	//就在原来文件最后加上段名字符串段
	g_shdr[STRTAB].sh_offset = (Elf32_Off)flen;
 	size_t szEhdr = sizeof(Elf32_Ehdr);
	//Elf头
	fwrite(&ehdr, szEhdr, 1, fw);
	//除了Elf头之外的原文件内容
	fwrite(buffer+szEhdr, flen-szEhdr, 1, fw);
	//补上段名字符串段
	fwrite(g_strtabcontent, shstrtabsz, 1, fw);
	//补上段表头
	fwrite(&g_shdr, sizeof(g_shdr), 1, fw);
	printf("fixed so has write to %s\n", outPutPath);

	if(fw != NULL)
		fclose(fw);
	if(fr != NULL)
		fclose(fr);
	free(buffer);
	return 0;
}
