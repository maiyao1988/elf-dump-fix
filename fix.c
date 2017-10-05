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

static void get_elf_header(Elf32_Ehdr *pehdr, const char *buffer)
{
	int header_len = sizeof(Elf32_Ehdr);
	memcpy(pehdr, (void*)buffer, header_len);
}

static long get_file_len(FILE* p)
{
	fseek (p, 0, SEEK_END);
	long fsize = ftell (p);
	rewind (p);
	return fsize;
}


static void regen_section_header(const Elf32_Ehdr *pehdr, const char *buffer)
{
	Elf32_Phdr load = { 0 };
	Elf32_Phdr *phdr = (Elf32_Phdr*)(buffer + pehdr->e_phoff);
	int ph_num = pehdr->e_phnum;
	int dyn_size = 0, dyn_off = 0;
	int nbucket = 0, nchain = 0;
	int i = 0;
	
	for(;i < ph_num;i++) {
		//段在文件中的偏移修正，因为从内存dump出来的文件偏移就是在内存的偏移
		phdr[i].p_offset =  phdr[i].p_vaddr;
		Elf32_Word p_type = phdr[i].p_type;
		if (phdr[i].p_type == PT_LOAD) {
			//实际上取的是最后一个PT_LOAD
			if (phdr[i].p_vaddr > 0x0) {
				load = phdr[i];
				g_shdr[BSS].sh_name = _get_off_in_shstrtab(".bss");
				g_shdr[BSS].sh_type = SHT_NOBITS;
				g_shdr[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
				g_shdr[BSS].sh_addr =  phdr[i].p_vaddr + phdr[i].p_filesz;
				g_shdr[BSS].sh_offset = g_shdr[BSS].sh_addr;
				g_shdr[BSS].sh_addralign = 1;
			}
		}
		else if(p_type == PT_DYNAMIC) {
			//动态表，动态表包括很多项，找到动态表位置可以恢复大部分结构,这个是恢复的突破口
			g_shdr[DYNAMIC].sh_name = _get_off_in_shstrtab(".dynamic");
			g_shdr[DYNAMIC].sh_type = SHT_DYNAMIC;
			g_shdr[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
			g_shdr[DYNAMIC].sh_addr = phdr[i].p_vaddr;
			g_shdr[DYNAMIC].sh_offset = phdr[i].p_offset;
			g_shdr[DYNAMIC].sh_size = phdr[i].p_filesz;
			g_shdr[DYNAMIC].sh_link = 2;
			g_shdr[DYNAMIC].sh_info = 0;
			g_shdr[DYNAMIC].sh_addralign = 4;
			g_shdr[DYNAMIC].sh_entsize = 8;
			dyn_size = phdr[i].p_filesz;
			dyn_off = phdr[i].p_offset;
		}
		
		else if(phdr[i].p_type == PT_LOPROC || phdr[i].p_type == PT_LOPROC + 1) {
			g_shdr[ARMEXIDX].sh_name = _get_off_in_shstrtab(".ARM.exidx");
			g_shdr[ARMEXIDX].sh_type = SHT_LOPROC;
			g_shdr[ARMEXIDX].sh_flags = SHF_ALLOC;
			g_shdr[ARMEXIDX].sh_addr = phdr[i].p_vaddr;
			g_shdr[ARMEXIDX].sh_offset = phdr[i].p_offset;
			g_shdr[ARMEXIDX].sh_size = phdr[i].p_filesz;
			g_shdr[ARMEXIDX].sh_link = 7;
			g_shdr[ARMEXIDX].sh_info = 0;
			g_shdr[ARMEXIDX].sh_addralign = 4;
			g_shdr[ARMEXIDX].sh_entsize = 8;
		}
	}
	
	const Elf32_Dyn* dyn = (const Elf32_Dyn*)(buffer+dyn_off);
	i = 0;
	int n = dyn_size / sizeof(Elf32_Dyn);
	
	Elf32_Word __global_offset_table = 0;
	for (; i < n; i++) {
		int tag = dyn[i].d_tag;
		switch (tag) {
			case DT_SYMTAB:
				g_shdr[DYNSYM].sh_name = _get_off_in_shstrtab(".dynsym");
				g_shdr[DYNSYM].sh_type = SHT_DYNSYM;
				g_shdr[DYNSYM].sh_flags = SHF_ALLOC;
				g_shdr[DYNSYM].sh_addr = dyn[i].d_un.d_ptr;
				g_shdr[DYNSYM].sh_offset = dyn[i].d_un.d_ptr;
				g_shdr[DYNSYM].sh_link = 2;
				g_shdr[DYNSYM].sh_info = 1;
				g_shdr[DYNSYM].sh_addralign = 4;
				g_shdr[DYNSYM].sh_entsize = 16;
				break;
				
			case DT_STRTAB:
				g_shdr[DYNSTR].sh_name = _get_off_in_shstrtab(".dynstr");
				g_shdr[DYNSTR].sh_type = SHT_STRTAB;
				g_shdr[DYNSTR].sh_flags = SHF_ALLOC;
				g_shdr[DYNSTR].sh_offset = dyn[i].d_un.d_ptr;
				g_shdr[DYNSTR].sh_addr = dyn[i].d_un.d_ptr;
				g_shdr[DYNSTR].sh_addralign = 1;
				g_shdr[DYNSTR].sh_entsize = 0;
				break;
				
			case DT_STRSZ:
				g_shdr[DYNSTR].sh_size = dyn[i].d_un.d_val;
				break;
				
			case DT_HASH:
				g_shdr[HASH].sh_name = _get_off_in_shstrtab(".hash");
				g_shdr[HASH].sh_type = SHT_HASH;
				g_shdr[HASH].sh_flags = SHF_ALLOC;
				g_shdr[HASH].sh_addr = dyn[i].d_un.d_ptr;
				g_shdr[HASH].sh_offset = dyn[i].d_un.d_ptr;
				memcpy(&nbucket, buffer + g_shdr[HASH].sh_offset, 4);
				memcpy(&nchain, buffer + g_shdr[HASH].sh_offset + 4, 4);
				g_shdr[HASH].sh_size = (nbucket + nchain + 2) * sizeof(int);
				g_shdr[HASH].sh_link = 4;
				g_shdr[HASH].sh_info = 1;
				g_shdr[HASH].sh_addralign = 4;
				g_shdr[HASH].sh_entsize = 4;
				break;
				
			case DT_REL:
				g_shdr[RELDYN].sh_name = _get_off_in_shstrtab(".rel.dyn");
				g_shdr[RELDYN].sh_type = SHT_REL;
				g_shdr[RELDYN].sh_flags = SHF_ALLOC;
				g_shdr[RELDYN].sh_addr = dyn[i].d_un.d_ptr;
				g_shdr[RELDYN].sh_offset = dyn[i].d_un.d_ptr;
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
				g_shdr[RELPLT].sh_addr = dyn[i].d_un.d_ptr;
				g_shdr[RELPLT].sh_offset = dyn[i].d_un.d_ptr;
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
				g_shdr[FINIARRAY].sh_offset = dyn[i].d_un.d_ptr;
				g_shdr[FINIARRAY].sh_addr = dyn[i].d_un.d_ptr;
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
				g_shdr[INITARRAY].sh_offset = dyn[i].d_un.d_ptr;
				g_shdr[INITARRAY].sh_addr = dyn[i].d_un.d_ptr;
				g_shdr[INITARRAY].sh_addralign = 4;
				g_shdr[INITARRAY].sh_entsize = 0;
				break;
				
			case DT_INIT_ARRAYSZ:
				g_shdr[INITARRAY].sh_size = dyn[i].d_un.d_ptr;
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
		//这种计算方式不可靠，根据libGameCore.so分析，nRelPlt比数量比实际GOT数量多10个，暂时没发现这十个成员的特殊性
		Elf32_Word gotEnd = __global_offset_table + 4 * (nRelPlt + 3);
		
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
			printf("warning .got is not after .dynamic use __global_offset_table to be .got base\n");
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

int main(int argc, char const *argv[])
{
	FILE *fr = NULL, *fw = NULL;
	char *buffer = NULL;
	
	if (argc < 2) {
		printf("<src_so_path> [base_addr_in_memory_in_hex] [<out_so_path>]\n");
		return -1;
	}
	const char *openPath = argv[1];
	const char *outPutPath = "fix.so";
	
	Elf32_Word base = 0;
	if (argc > 2)
	{
		base = (Elf32_Word)strtoul(argv[2], 0, 16);
		outPutPath = argv[2];
	}
	
	if (argc > 3)
	{
		outPutPath = argv[3];
	}
	fr = fopen(openPath,"rb");
	
	if(fr == NULL) {
		printf("Open failed: \n");
		goto error;
	}
	
	size_t flen = get_file_len(fr);
	
	buffer = (char*)malloc(flen);
	if (buffer == NULL) {
		printf("Malloc error\n");
		goto error;
	}
	
	unsigned long result = fread (buffer, 1, flen, fr);
	if (result != flen) {
		printf("Reading %s error\n", openPath);
		goto error;
	}
	fw = fopen(outPutPath, "wb");
	if(fw == NULL) {
		printf("Open failed: %s\n", outPutPath);
		goto error;
	}
	
	Elf32_Ehdr ehdr = {0};
	get_elf_header(&ehdr, buffer);
	
	regen_section_header(&ehdr, buffer);
	
	size_t shstrtabsz = strlen(g_str)+1;
	ehdr.e_entry = base;
	ehdr.e_shnum = SHDRS;
	//倒数第一个为段名字符串段
	ehdr.e_shstrndx = SHDRS - 1;
	
	//就在原来文件最后加上段名字符串段
	g_shdr[STRTAB].sh_offset = (Elf32_Off)flen;
	//段表头紧接住段表最后一个成员--字符串段之后
	ehdr.e_shoff = (Elf32_Off)(flen + shstrtabsz);
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
error:
	if(fw != NULL)
		fclose(fw);
	if(fr != NULL)
		fclose(fr);
	free(buffer);
	return 0;
}
