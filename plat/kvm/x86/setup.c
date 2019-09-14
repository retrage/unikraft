/* SPDX-License-Identifier: ISC */
/*
 * Authors: Dan Williams
 *          Martin Lucina
 *          Ricardo Koller
 *          Felipe Huici <felipe.huici@neclab.eu>
 *          Florian Schmidt <florian.schmidt@neclab.eu>
 *          Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2015-2017 IBM
 * Copyright (c) 2016-2017 Docker, Inc.
 * Copyright (c) 2017 NEC Europe Ltd., NEC Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>
#include <sections.h>
#include <x86/cpu.h>
#include <x86/traps.h>
#include <kvm/config.h>
#include <kvm/console.h>
#include <kvm/intctrl.h>
#include <kvm-x86/multiboot.h>
#include <kvm-x86/multiboot_defs.h>
#include <kvm-x86/eficall.h>
#include <uk/arch/limits.h>
#include <uk/arch/types.h>
#include <uk/plat/console.h>
#include <uk/assert.h>
#include <uk/essentials.h>
#include <Uefi.h>
#include <GlobalTable.h>
#include <Protocol/LoadedImage.h>

#define PLATFORM_MEM_START 0x100000
#define PLATFORM_MAX_MEM_ADDR 0x40000000

#define MAX_CMDLINE_SIZE 8192
static char cmdline[MAX_CMDLINE_SIZE];
static uintptr_t reloc_region_addr;
static size_t reloc_region_size;

struct kvmplat_config _libkvmplat_cfg = { 0 };

extern void _libkvmplat_newstack(uintptr_t stack_start, void (*tramp)(void *),
				 void *arg);

extern void _libkvmplat_start64(void);

static void *_efi_alloc_reloc_region(uintptr_t addr, size_t size)
{
    int found;
    void *ptr;
    UINTN map_size;
    VOID *buffer;
    UINTN map_key;
    UINTN desc_size;
    UINT32 desc_version;
    EFI_MEMORY_DESCRIPTOR *mem_desc;
    UINTN start;
    UINTN pages;
    EFI_STATUS status;

	if (!gBS)
      return NULL;

    map_size = __PAGE_SIZE;
    do {
      status = efi_call3(gBS->AllocatePool, EfiLoaderData, map_size, &buffer);
      if (EFI_ERROR(status))
        return NULL;
      status = efi_call5(gBS->GetMemoryMap, &map_size, buffer, &map_key,
                          &desc_size, &desc_version);
      if (status == EFI_BUFFER_TOO_SMALL) {
        status = efi_call1(gBS->FreePool, buffer);
        if (EFI_ERROR(status))
          return NULL;
        map_size <<= 1;
      } else if (EFI_ERROR(status))
        return NULL;
    } while (EFI_ERROR(status));

    found = 0;
    ptr = (void *)buffer;
    while (ptr - (void *)buffer < map_size) {
      mem_desc = (EFI_MEMORY_DESCRIPTOR *)ptr;
      start = mem_desc->PhysicalStart;
      pages = mem_desc->NumberOfPages;
      if (mem_desc->Type == EfiConventionalMemory) {
        if (start <= addr && addr + size <= start + __PAGE_SIZE * pages) {
          found = 1;
          break;
        }
      }
      ptr += desc_size;
    }

    status = efi_call1(gBS->FreePool, buffer);
    if (EFI_ERROR(status))
      return NULL;

    if (!found)
      return NULL;

    reloc_region_addr = start;
    reloc_region_size = __PAGE_SIZE * pages;
    /* Allocate all available pages in the region. */
    status = efi_call4(gBS->AllocatePages, AllocateAddress, EfiLoaderData,
                        pages, &start);
    if (EFI_ERROR(status))
      return NULL;

    efi_call3(gBS->CopyMem, (void *)addr, (void *)__TEXT, size);

    return (void *)addr;
}

static inline void _efi_get_cmdline()
{
	int i;
    CHAR16 *load_opt;
    size_t opt_size;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
    EFI_STATUS status;

    if (!gBS)
      goto done;

    status = efi_call3(gBS->HandleProtocol,
                        gImageHandle, &loaded_image_guid, &loaded_image);
    if (EFI_ERROR(status)) {
      /* Use image name as cmdline to provide argv[0] */
      strncpy(cmdline, CONFIG_UK_NAME, sizeof(cmdline));
      uk_pr_err("EFI Loaded Image Protocol not found\n");
      goto done;
    }

    load_opt = (CHAR16 *)loaded_image->LoadOptions;
    opt_size = loaded_image->LoadOptionsSize / (sizeof(CHAR16) / sizeof(char));
    if (opt_size > sizeof(cmdline)) {
      uk_pr_err("Command line too long, truncated\n");
      opt_size = cmdline - 1;
    }

    if (opt_size > 0) {
      for (i = 0; i < opt_size; i++)
        cmdline[i] = (char)(load_opt[i] & 0x00ff);
    } else {
	  uk_pr_debug("No command line present\n");
    }

done:
	/* ensure null termination */
	cmdline[(sizeof(cmdline) - 1)] = '\0';
}

static inline void _efi_init_mem()
{
	size_t max_addr;

	/*
	 * Cap our memory size to PLATFORM_MAX_MEM_SIZE which boot.S defines
	 * page tables for.
	 */
	max_addr = reloc_region_addr + reloc_region_size;
	if (max_addr > PLATFORM_MAX_MEM_ADDR)
		max_addr = PLATFORM_MAX_MEM_ADDR;
	UK_ASSERT((size_t) __END <= max_addr);

	/*
	 * Reserve space for boot stack at the end of found memory
	 */
	if ((max_addr - reloc_region_addr) < __STACK_SIZE)
		UK_CRASH("Not enough memory to allocate boot stack\n");

	_libkvmplat_cfg.heap.start = ALIGN_UP((uintptr_t) __END, __PAGE_SIZE);
	_libkvmplat_cfg.heap.end   = (uintptr_t) max_addr - __STACK_SIZE;
	_libkvmplat_cfg.heap.len   = _libkvmplat_cfg.heap.end
				     - _libkvmplat_cfg.heap.start;
	_libkvmplat_cfg.bstack.start = _libkvmplat_cfg.heap.end;
	_libkvmplat_cfg.bstack.end   = max_addr;
	_libkvmplat_cfg.bstack.len   = __STACK_SIZE;
}

static inline void _efi_init_initrd()
{
    /* Do nothing */
}

static inline void _efi_exit_bootservices()
{
    UINTN map_size;
    VOID *buffer;
    UINTN map_key;
    UINTN desc_size;
    UINT32 desc_version;
    EFI_STATUS status;

	if (!gBS)
      return NULL;

    map_size = __PAGE_SIZE;
    do {
      status = efi_call3(gBS->AllocatePool, EfiLoaderData, map_size, &buffer);
      if (EFI_ERROR(status))
        return NULL;
      status = efi_call5(gBS->GetMemoryMap, &map_size, buffer, &map_key,
                          &desc_size, &desc_version);
      if (status == EFI_BUFFER_TOO_SMALL) {
        status = efi_call1(gBS->FreePool, buffer);
        if (EFI_ERROR(status))
          return NULL;
        map_size <<= 1;
      } else if (EFI_ERROR(status))
        return NULL;
    } while (EFI_ERROR(status));

    status = efi_call2(gBS->ExitBootServices, gImageHandle, map_key);
    if (EFI_ERROR(status))
      uk_pr_err("EFI ExitBootServices failed: Status=%d\n", status);
}

static void _libkvmplat_entry2(void *arg __attribute__((unused)))
{
	ukplat_entry_argp(NULL, cmdline, sizeof(cmdline));
}

void _libkvmplat_entry()
{
	_init_cpufeatures();
	_libkvmplat_init_console();
	traps_init();
	intctrl_init();

	uk_pr_info("Entering from KVM (x86)...\n");
	uk_pr_info("     EFI System Table: %p\n", *gST);

    _efi_get_cmdline();
    _efi_init_mem();
    _efi_init_initrd();
    _efi_exit_bootservices();

	if (_libkvmplat_cfg.initrd.len)
		uk_pr_info("        initrd: %p\n",
			   (void *) _libkvmplat_cfg.initrd.start);
	uk_pr_info("    heap start: %p\n",
		   (void *) _libkvmplat_cfg.heap.start);
	if (_libkvmplat_cfg.heap2.len)
		uk_pr_info(" heap start (2): %p\n",
			   (void *) _libkvmplat_cfg.heap2.start);
	uk_pr_info("     stack top: %p\n",
		   (void *) _libkvmplat_cfg.bstack.start);

	/*
	 * Switch away from the bootstrap stack as early as possible.
	 */
	uk_pr_info("Switch from bootstrap stack to stack @%p\n",
		   (void *) _libkvmplat_cfg.bstack.end);

	_libkvmplat_newstack(_libkvmplat_cfg.bstack.end,
                         _libkvmplat_entry2, 0);
}

void _libkvmplat_efi_setup(EFI_HANDLE image_handle,
    EFI_SYSTEM_TABLE *system_table)
{
  uintptr_t addr;
  size_t size;
  void *reloc_region;

  /* Initialize global table pointers. */
  gImageHandle = image_handle;
  gST = system_table;
  gBS = gST->BootServices;

  addr = PLATFORM_MEM_START;
  size = ALIGN_UP(__END - __TEXT, __PAGE_SIZE);

  reloc_region = _efi_alloc_reloc_region(addr, size);
  if (!reloc_region)
    return;

  /* Call startup function where in the relocated region. */
  _libkvmplat_start64();
}
