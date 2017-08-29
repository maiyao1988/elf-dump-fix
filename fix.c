#define _CRT_SECURE_NO_WARNINGS
#include "fix.h"

char* str = "..dynsym..dynstr..hash..rel.dyn..rel.plt..plt..text@.ARM.extab..ARM.exidx..fini_array..init_array..dynamic..got..data..bss..shstrtab\0";
char* str1 = "\0.dynsym\0.dynstr\0.hash\0.rel.dyn\0.rel.plt\0.plt\0.text@.ARM.extab\0.ARM.exidx\0.fini_array\0.init_array\0.dynamic\0.got\0.data\0.bss\0.shstrtab\0";
Elf32_Shdr shdr[SHDRS] = { 0 };

void get_elf_header(char* buffer,Elf32_Ehdr** pehdr)
{
	int header_len = sizeof(Elf32_Ehdr);
	memset(*pehdr, 0, header_len);
	memcpy(*pehdr, (void*)buffer, header_len);
}

void get_program_table(Elf32_Ehdr ehdr,char* buffer,Elf32_Phdr** pphdr)
{
	int ph_size = ehdr.e_phentsize;
	int ph_num = ehdr.e_phnum;
	memset(*pphdr, 0, ph_size * ph_num);
	memcpy(*pphdr, buffer + ehdr.e_phoff,ph_size * ph_num);
}

long get_file_len(FILE* p)
{
    fseek (p, 0, SEEK_END);
    long fsize = ftell (p);
    rewind (p);
    return fsize; 
}


void get_Info(Elf32_Phdr* phdr, Elf32_Ehdr *pehdr, char* buffer)
{
	Elf32_Dyn* dyn = NULL;
	Elf32_Dyn* d = NULL;
	Elf32_Phdr load = { 0 };
	
	int ph_num = pehdr->e_phnum;
	int dyn_size = 0, dyn_off = 0;
	int nbucket = 0, nchain = 0;
	int flag = 0, i = 0;

	for(;i < ph_num;i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (phdr[i].p_vaddr > 0x0) {
				load = phdr[i];
				shdr[BSS].sh_name = strstr(str,".bss") - str;
				shdr[BSS].sh_type = SHT_NOBITS;
				shdr[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
				shdr[BSS].sh_addr =  phdr[i].p_vaddr + phdr[i].p_filesz;
				shdr[BSS].sh_offset = shdr[BSS].sh_addr - 0x1000;
				shdr[BSS].sh_addralign = 1;

				continue;
			}
		}

		if(phdr[i].p_type == PT_DYNAMIC) {
			shdr[DYNAMIC].sh_name = strstr(str, ".dynamic") - str;
			shdr[DYNAMIC].sh_type = SHT_DYNAMIC;
			shdr[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
			shdr[DYNAMIC].sh_addr = phdr[i].p_vaddr;
			shdr[DYNAMIC].sh_offset = phdr[i].p_offset;
			shdr[DYNAMIC].sh_size = phdr[i].p_filesz;
			shdr[DYNAMIC].sh_link = 2;
			shdr[DYNAMIC].sh_info = 0;
			shdr[DYNAMIC].sh_addralign = 4;
			shdr[DYNAMIC].sh_entsize = 8;
			dyn_size = phdr[i].p_filesz;
    		dyn_off = phdr[i].p_offset;
    		continue;
		}

		if(phdr[i].p_type == PT_LOPROC || phdr[i].p_type == PT_LOPROC + 1) {
			shdr[ARMEXIDX].sh_name = strstr(str, ".ARM.exidx") - str;
			shdr[ARMEXIDX].sh_type = SHT_LOPROC;
			shdr[ARMEXIDX].sh_flags = SHF_ALLOC;
			shdr[ARMEXIDX].sh_addr = phdr[i].p_vaddr;
			shdr[ARMEXIDX].sh_offset = phdr[i].p_offset;
			shdr[ARMEXIDX].sh_size = phdr[i].p_filesz;
			shdr[ARMEXIDX].sh_link = 7;
			shdr[ARMEXIDX].sh_info = 0;
			shdr[ARMEXIDX].sh_addralign = 4;
			shdr[ARMEXIDX].sh_entsize = 8;
			continue;
		}
	}

	dyn = (Elf32_Dyn*)malloc(dyn_size);
	memcpy(dyn,buffer+dyn_off,dyn_size);
	i = 0;
	for (; i < dyn_size / sizeof(Elf32_Dyn); i++) {
		switch (dyn[i].d_tag) {
			case DT_SYMTAB:
				shdr[DYNSYM].sh_name = strstr(str, ".dynsym") - str;
				shdr[DYNSYM].sh_type = SHT_DYNSYM;
				shdr[DYNSYM].sh_flags = SHF_ALLOC;
				shdr[DYNSYM].sh_addr = dyn[i].d_un.d_ptr;
				shdr[DYNSYM].sh_offset = dyn[i].d_un.d_ptr;
				shdr[DYNSYM].sh_link = 2;
				shdr[DYNSYM].sh_info = 1;
				shdr[DYNSYM].sh_addralign = 4;
				shdr[DYNSYM].sh_entsize = 16;
				break;

			case DT_STRTAB:
				shdr[DYNSTR].sh_name = strstr(str, ".dynstr") - str;
				shdr[DYNSTR].sh_type = SHT_STRTAB;
				shdr[DYNSTR].sh_flags = SHF_ALLOC;
				shdr[DYNSTR].sh_offset = dyn[i].d_un.d_ptr;
				shdr[DYNSTR].sh_addr = dyn[i].d_un.d_ptr;
				shdr[DYNSTR].sh_addralign = 1;
				shdr[DYNSTR].sh_entsize = 0;
				break;

			case DT_HASH:
				shdr[HASH].sh_name = strstr(str, ".hash") - str;
				shdr[HASH].sh_type = SHT_HASH;
				shdr[HASH].sh_flags = SHF_ALLOC;
				shdr[HASH].sh_addr = dyn[i].d_un.d_ptr;
				shdr[HASH].sh_offset = dyn[i].d_un.d_ptr;
				memcpy(&nbucket, buffer + shdr[HASH].sh_offset, 4);
				memcpy(&nchain, buffer + shdr[HASH].sh_offset + 4, 4);
				shdr[HASH].sh_size = (nbucket + nchain + 2) * sizeof(int);
				shdr[HASH].sh_link = 4;
				shdr[HASH].sh_info = 1;
				shdr[HASH].sh_addralign = 4;
				shdr[HASH].sh_entsize = 4;
				break;

			case DT_REL:
				shdr[RELDYN].sh_name = strstr(str, ".rel.dyn") - str;
				shdr[RELDYN].sh_type = SHT_REL;
				shdr[RELDYN].sh_flags = SHF_ALLOC;
				shdr[RELDYN].sh_addr = dyn[i].d_un.d_ptr;
				shdr[RELDYN].sh_offset = dyn[i].d_un.d_ptr;
				shdr[RELDYN].sh_link = 4;
				shdr[RELDYN].sh_info = 0;
				shdr[RELDYN].sh_addralign = 4;
				shdr[RELDYN].sh_entsize = 8;
				break;

			case DT_JMPREL:
				shdr[RELPLT].sh_name = strstr(str, ".rel.plt") - str;
				shdr[RELPLT].sh_type = SHT_REL;
				shdr[RELPLT].sh_flags = SHF_ALLOC;
				shdr[RELPLT].sh_addr = dyn[i].d_un.d_ptr;
				shdr[RELPLT].sh_offset = dyn[i].d_un.d_ptr;
				shdr[RELPLT].sh_link = 1;
				shdr[RELPLT].sh_info = 6;
				shdr[RELPLT].sh_addralign = 4;
				shdr[RELPLT].sh_entsize = 8;
				break;

			case DT_PLTRELSZ:
				shdr[RELPLT].sh_size = dyn[i].d_un.d_val;
				break;

			case DT_FINI:
				shdr[FINIARRAY].sh_name = strstr(str, ".fini_array") - str;
				shdr[FINIARRAY].sh_type = 15;
				shdr[FINIARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
				shdr[FINIARRAY].sh_offset = dyn[i].d_un.d_ptr - 0x1000;
				shdr[FINIARRAY].sh_addr = dyn[i].d_un.d_ptr;
				shdr[FINIARRAY].sh_addralign = 4;
				shdr[FINIARRAY].sh_entsize = 0;
				break;

			case DT_INIT:
				shdr[INITARRAY].sh_name = strstr(str, ".init_array") - str;
				shdr[INITARRAY].sh_type = 14;
				shdr[INITARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
				shdr[INITARRAY].sh_offset = dyn[i].d_un.d_ptr - 0x1000;
				shdr[INITARRAY].sh_addr = dyn[i].d_un.d_ptr;
				shdr[INITARRAY].sh_addralign = 4;
				shdr[INITARRAY].sh_entsize = 0;
				break;

			case DT_RELSZ:
				shdr[RELDYN].sh_size = dyn[i].d_un.d_val;
				break;
			
			case DT_STRSZ:
				shdr[DYNSTR].sh_size = dyn[i].d_un.d_val;
				break;

			case DT_PLTGOT:
				shdr[GOT].sh_name = strstr(str, ".got") - str;
				shdr[GOT].sh_type = SHT_PROGBITS;
				shdr[GOT].sh_flags = SHF_WRITE | SHF_ALLOC; 
				shdr[GOT].sh_addr = shdr[DYNAMIC].sh_addr + shdr[DYNAMIC].sh_size;
				shdr[GOT].sh_offset = shdr[GOT].sh_addr - 0x1000;
				shdr[GOT].sh_size = dyn[i].d_un.d_ptr;
				shdr[GOT].sh_addralign = 4;
				break;
		}
	}
	shdr[GOT].sh_size = shdr[GOT].sh_size + 4 * (shdr[RELPLT].sh_size) / sizeof(Elf32_Rel) + 3 * sizeof(int) - shdr[GOT].sh_addr;

	//STRTAB地址 - SYMTAB地址 = SYMTAB大小
	shdr[DYNSYM].sh_size = shdr[DYNSTR].sh_addr - shdr[DYNSYM].sh_addr;

	shdr[FINIARRAY].sh_size = shdr[INITARRAY].sh_addr - shdr[FINIARRAY].sh_addr;
	shdr[INITARRAY].sh_size = shdr[DYNAMIC].sh_addr - shdr[INITARRAY].sh_addr;
	
	shdr[PLT].sh_name = strstr(str, ".plt") - str;
	shdr[PLT].sh_type = SHT_PROGBITS;
	shdr[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	shdr[PLT].sh_addr = shdr[RELPLT].sh_addr + shdr[RELPLT].sh_size;
	shdr[PLT].sh_offset = shdr[PLT].sh_addr;
	shdr[PLT].sh_size = (20 + 12 * (shdr[RELPLT].sh_size) / sizeof(Elf32_Rel));
	shdr[PLT].sh_addralign = 4;

	shdr[TEXT].sh_name = strstr(str, ".text") - str;
	shdr[TEXT].sh_type = SHT_PROGBITS;
	shdr[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	shdr[TEXT].sh_addr = shdr[PLT].sh_addr + shdr[PLT].sh_size;
	shdr[TEXT].sh_offset = shdr[TEXT].sh_addr;
	shdr[TEXT].sh_size = shdr[ARMEXIDX].sh_addr - shdr[TEXT].sh_addr;
	
	shdr[DATA].sh_name = strstr(str, ".data") - str;
	shdr[DATA].sh_type = SHT_PROGBITS;
	shdr[DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
	shdr[DATA].sh_addr = shdr[GOT].sh_addr + shdr[GOT].sh_size;
	shdr[DATA].sh_offset = shdr[DATA].sh_addr - 0x1000;
	shdr[DATA].sh_size = load.p_vaddr + load.p_filesz - shdr[DATA].sh_addr;
	shdr[DATA].sh_addralign = 4;
	shdr[GOT].sh_size = shdr[DATA].sh_offset - shdr[GOT].sh_offset;

	shdr[STRTAB].sh_name = strstr(str, ".shstrtab") - str;
	shdr[STRTAB].sh_type = SHT_STRTAB;
	shdr[STRTAB].sh_flags = SHT_NULL;
	shdr[STRTAB].sh_addr = 0;
	shdr[STRTAB].sh_offset = shdr[BSS].sh_addr - 0x1000;
	shdr[STRTAB].sh_size = strlen(str) + 1;
	shdr[STRTAB].sh_addralign = 1;
}

int main(int argc, char const *argv[])
{
	FILE* fr = NULL,* fw = NULL;
	long flen = 0,result = 0;
	char* buffer = NULL;
	Elf32_Ehdr *pehdr = NULL;
	Elf32_Phdr* pphdr = NULL;

	if (argc < 2) {
		printf("less args\n");
		return;
	}

	fr = fopen(argv[1],"rb");
	if(fr == NULL) {
		printf("Open failed: \n");
		goto error;
	}

	flen = get_file_len(fr);

	buffer = (char*)malloc(sizeof(char)*flen);
	if (buffer == NULL) {
		printf("Malloc error\n");
		goto error;
	}

	result = fread (buffer,1,flen,fr);
	if (result != flen) {
		printf("Reading error\n");
		goto error;
	}

	fw = fopen("fix.so","wb");
	if(fw == NULL) {
		printf("Open failed: fix.so\n");
		goto error;
	}
	
	pehdr = (Elf32_Ehdr*)malloc(sizeof(Elf32_Ehdr));
	get_elf_header(buffer, &pehdr);

	pphdr = (Elf32_Phdr*)malloc(pehdr->e_phentsize * pehdr->e_phnum);
	get_program_table(*pehdr, buffer, &pphdr);

	get_Info(pphdr, pehdr, buffer);
	
	pehdr->e_shnum = SHDRS;
	pehdr->e_shstrndx = SHDRS - 1;
	pehdr->e_shoff = shdr[STRTAB].sh_offset + strlen(str) + 1;
	memcpy(buffer, pehdr, sizeof(Elf32_Ehdr));
	memcpy(buffer + shdr[GOT].sh_offset, buffer + shdr[GOT].sh_offset + 0x1000, shdr[GOT].sh_size);
	//memset(buffer + shdr[DATA].sh_offset, 0, shdr[DATA].sh_offset);
	memcpy(buffer + shdr[STRTAB].sh_offset, str1, strlen(str) + 1);
	memcpy(buffer + pehdr->e_shoff, shdr, pehdr->e_shentsize * pehdr->e_shnum);
	flen = shdr[STRTAB].sh_offset + strlen(str) + 1 + SHDRS * sizeof(Elf32_Shdr);
	fwrite(buffer, sizeof(char)*flen, 1, fw);

error:
	if(fw != NULL)
		fclose(fw);
	if(fr != NULL)
		fclose(fr);
	if(buffer != NULL)
		free(buffer);
	return 0;
}