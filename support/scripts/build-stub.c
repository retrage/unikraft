/* SPDX-License-Identifier: MIT */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "pe.h"

#define ALIGN_UP(val, align) ((val + align - 1) & ~(align - 1))

const size_t ALIGN = 0x1000;
const size_t STRSIZE = 1024;

unsigned int address_of_entry_point;
unsigned int size_of_code;
unsigned int base_of_code;
unsigned int size_of_image;
unsigned int text_size;
unsigned int text_addr;
unsigned int rodata_size;
unsigned int rodata_addr;
unsigned int data_size;
unsigned int data_addr;
unsigned int bss_size;
unsigned int bss_addr;

static void parse_symbol_table(const char *sym_name)
{
  FILE *sym_fp = fopen(sym_name, "r");
  if (!sym_fp) {
    fprintf(stderr, "Could not open file %s\n", sym_name);
    return;
  }

  const char *TEXT = "_text";
  const char *EHDR = "_ehdr";
  const char *ENTRY = "_libkvmplat_efi_start";
  const char *RODATA = "_rodata";
  const char *DATA = "_data";
  const char *BSS = "__bss_start";
  const char *END = "_end";

  unsigned long long offset = 0;
  unsigned int text = 0;
  unsigned int rodata = 0;
  unsigned int data = 0;
  unsigned int bss = 0;
  unsigned int end = 0;

  unsigned long long addr;
  char c;
  char sym[STRSIZE];
  while (fscanf(sym_fp, "%llx %c %s", &addr, &c, sym) != EOF) {
    if (!strncmp(sym, TEXT, STRSIZE)) {
      offset = addr;
    } else if (!strncmp(sym, EHDR, STRSIZE)) {
      text = ALIGN_UP(addr, ALIGN) - offset;
    } else if (!strncmp(sym, ENTRY, STRSIZE)) {
      address_of_entry_point = addr - offset;
    } else if (!strncmp(sym, RODATA, STRSIZE)) {
      if (offset != 0 && rodata == 0)
        rodata = addr - offset;
    } else if (!strncmp(sym, DATA, STRSIZE)) {
      if (offset != 0 && data == 0)
        data = addr - offset;
    } else if (!strncmp(sym, BSS, STRSIZE)) {
      if (offset != 0 && bss == 0)
        bss = addr - offset;
    } else if (!strncmp(sym, END, STRSIZE)) {
      if (offset != 0)
        end = addr - offset;
    }
   }

  text_size = ALIGN_UP(rodata - text, ALIGN);
  text_addr = text;
  rodata_size = ALIGN_UP(data - rodata, ALIGN);
  rodata_addr = rodata;
  data_size = ALIGN_UP(bss - data, ALIGN);
  data_addr = data;
  bss_size = ALIGN_UP(end - bss, ALIGN);
  bss_addr = bss;

  base_of_code = text_addr;
  size_of_code = text_size;
  size_of_image = end;

  fclose(sym_fp);
}

int main(int argc, char *argv[])
{
  if (argc < 4) {
    fprintf(stderr, "Usage: %s SymbolTable INPUT OUTPUT\n", argv[0]);
    return 1;
  }

  parse_symbol_table(argv[1]);

  char bin_name[STRSIZE];
  strncpy(bin_name, argv[2], STRSIZE);
  int bin_fd = open(bin_name, O_RDONLY);
  if (bin_fd == -1) {
    fprintf(stderr, "Could not open file %s\n", bin_name);
    goto fail;
  }

  FILE *bin_fp = fdopen(bin_fd, "rb");
  if (!bin_fp) {
    fprintf(stderr, "Could not open file %s\n", bin_name);
    goto fail;
  }

  struct stat bin_st;
  if (fstat(bin_fd, &bin_st) == -1) {
    fprintf(stderr, "fstat failed\n");
    goto fail;
  }

  size_t bin_size = bin_st.st_size;
  void *bin_buf = malloc(bin_size);
  if (!bin_buf) {
    fprintf(stderr, "Could not allocate memory\n");
    goto fail;
  }

  if (fread(bin_buf, 1, bin_size, bin_fp) != bin_size) {
    fprintf(stderr, "Cound not read file\n");
    goto fail;
  }

  IMAGE_DOS_HEADER *doshdr = (IMAGE_DOS_HEADER *)bin_buf;
  if (doshdr->e_magic != MAGIC_MZ) {
    fprintf(stderr, "DOS header magic not found\n");
    goto fail;
  }

  IMAGE_NT_HEADERS *nthdr \
    = (IMAGE_NT_HEADERS *)((void *)doshdr + doshdr->e_lfanew);
  if (nthdr->Signature != MAGIC_PE) {
    fprintf(stderr, "PE header signature not found\n");
    goto fail;
  }

  IMAGE_FILE_HEADER *fhdr = &nthdr->FileHeader;
  IMAGE_OPTIONAL_HEADER *opthdr = &nthdr->OptionalHeader;

  opthdr->AddressOfEntryPoint = address_of_entry_point;
  opthdr->SizeOfCode = size_of_code;
  opthdr->BaseOfCode = base_of_code;
  opthdr->SizeOfImage = size_of_image;

  const char *TEXT = ".text";
  const char *RODATA = ".rodata";
  const char *DATA = ".data";
  const char *BSS = ".bss";

  for (int i = 0; i < fhdr->NumberOfSections; i++) {
    IMAGE_SECTION_HEADER *sechdr \
      = ((void *)nthdr + sizeof(IMAGE_NT_HEADERS)
          + sizeof(IMAGE_SECTION_HEADER) * i);
    if (!strncmp(sechdr->Name, TEXT, IMAGE_SIZEOF_SHORT_NAME)) {
      sechdr->Misc.VirtualSize = text_size;
      sechdr->VirtualAddress = text_addr;
      sechdr->SizeOfRawData = text_size;
      sechdr->PointerToRawData = text_addr;
    } else if (!strncmp(sechdr->Name, RODATA, IMAGE_SIZEOF_SHORT_NAME)) {
      sechdr->Misc.VirtualSize = rodata_size;
      sechdr->VirtualAddress = rodata_addr;
      sechdr->SizeOfRawData = rodata_size;
      sechdr->PointerToRawData = rodata_addr;
    } else if (!strncmp(sechdr->Name, DATA, IMAGE_SIZEOF_SHORT_NAME)) {
      sechdr->Misc.VirtualSize = data_size;
      sechdr->VirtualAddress = data_addr;
      sechdr->SizeOfRawData = data_size;
      sechdr->PointerToRawData = data_addr;
    } else if (!strncmp(sechdr->Name, BSS, IMAGE_SIZEOF_SHORT_NAME)) {
      sechdr->Misc.VirtualSize = bss_size;
      sechdr->VirtualAddress = bss_addr;
      sechdr->SizeOfRawData = bss_size;
      sechdr->PointerToRawData = bss_addr;
    }
  }

  void *wbuf = malloc(size_of_image);
  memset(wbuf, 0, size_of_image);
  memcpy(wbuf, bin_buf, size_of_image);

  FILE *wfp = fopen(argv[3], "wb");
  fwrite(wbuf, size_of_image, 1, wfp);
  fclose(wfp);

  return 0;

fail:
  if (bin_buf)
    free(bin_buf);
  if (bin_fp)
    fclose(bin_fp);
  if (bin_fd != -1)
    close(bin_fd);

  return 1;
}
