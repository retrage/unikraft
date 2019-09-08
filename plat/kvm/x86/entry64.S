/* SPDX-License-Identifier: BSD-2-Clause */
/*-
 * Copyright (c) 2016 Martin Lucina.  All Rights Reserved.
 *
 * Based on rumprun/hw arch/amd64/locore.S, which is:
 * Copyright (c) 2014, 2015 Antti Kantee.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <x86/cpu_defs.h>
#include <kvm-x86/traps.h>

#define ENTRY(x) .globl x; .type x,%function; x:
#define END(x)   .size x, . - x

.section .data.header

_hdr:
/* DOS Header */
dos_header:
.ascii "MZ"                             /* e_magic */
.fill 0x3a, 1, 0
.long coff_header - dos_header          /* e_lfanew */

/* COFF Header */
coff_header:
.ascii "PE\0\0"                         /* Signature */

/* File Header */
file_header:
.word 0x8664                            /* Machine */
.word 0x0004                            /* NumberOfSections */
.long 0x00000000                        /* TimeDateStamp */
.long 0x00000000                        /* PointerToSymbolTable */
.long 0x00000000                        /* NumberOfSymbols */
.word section_header - optional_header  /* SizeOfOptionalHeader */
.word 0x0002                            /* Characteristics */

/* Optional Header */
optional_header:
.word 0x020b                            /* Magic */
.byte 0x00
.byte 0x00
.long 0x00000000                        /* FILLED: SizeOfCode */
.long 0x00000000
.long 0x00000000
.long 0x00000000                        /* FILLED: AddressOfEntryPoint */
.long 0x00000000                        /* FILLED: BaseOfCode */

.quad 0x0000000000000000                /* ImageBase */
.long 0x00001000                        /* SectionAlignment */
.long 0x00001000                        /* FileAlignment */
.word 0x0000
.word 0x0000
.word 0x0000
.word 0x0000
.word 0x0000
.word 0x0000
.long 0x00000000
.long 0x00000000                        /* FILLED: SizeOfImage */
.long _ehdr - _hdr                      /* SizeOfHeaders */
.long 0x00000000                        /* FIXME: Checksum */
.word 0x000a                            /* Subsystem */
.word 0x0000
.quad 0x0000000000000000
.quad 0x0000000000000000
.quad 0x0000000000000000
.quad 0x0000000000000000
.long 0x00000000
.long 0x00000010                        /* NumberOfRvaAndSizes */
.fill 0x20,4,0x00000000                 /* DataDirectory */

/* Section Header */
section_header:
.ascii ".text\0\0\0"                    /* Name */
.long 0x00000000                        /* FILLED: VirtualSize */
.long 0x00000000                        /* FILLED: VirtualAddress */
.long 0x00000000                        /* FILLED: SizeOfRawData */
.long 0x00000000                        /* FILLED: PointerToRawData */
.long 0x00000000
.long 0x00000000
.word 0x0000
.word 0x0000
.long 0x60000020 /* r-x exec */         /* Characteristics */

.ascii ".rodata\0"
.long 0x00000000                        /* FILLED: VirtualSize */
.long 0x00000000                        /* FILLED: VirtualAddress */
.long 0x00000000                        /* FILLED: SizeOfRawData */
.long 0x00000000                        /* FILLED: PointerToRawData */
.long 0x00000000
.long 0x00000000
.word 0x0000
.word 0x0000
.long 0x42000040 /* r-- inited */

.ascii ".data\0\0\0"
.long 0x00000000                        /* FILLED: VirtualSize */
.long 0x00000000                        /* FILLED: VirtualAddress */
.long 0x00000000                        /* FILLED: SizeOfRawData */
.long 0x00000000                        /* FILLED: PointerToRawData */
.long 0x00000000
.long 0x00000000
.word 0x0000
.word 0x0000
.long 0xc8000080 /* rw- uninited */

.ascii ".bss\0\0\0\0"
.long 0x00000000                        /* FILLED: VirtualSize */
.long 0x00000000                        /* FILLED: VirtualAddress */
.long 0x00000000                        /* FILLED: SizeOfRawData */
.long 0x00000000                        /* FILLED: PointerToRawData */
.long 0x00000000
.long 0x00000000
.word 0x0000
.word 0x0000
.long 0xc8000040 /* rw- inited */

_ehdr:

/*
 * amd64 programmer's manual:
 *
 * "In long mode, segmentation is not used ... except for a few exceptions."
 *
 * Uuuyea, exceptions.
 */

.section .data.boot
.align 64
gdt64:
	.quad 0x0000000000000000
gdt64_cs:
	.quad GDT_DESC_CODE_VAL		/* 64bit CS		*/
gdt64_ds:
	.quad GDT_DESC_DATA_VAL		/* DS			*/
	.quad 0x0000000000000000	/* TSS part 1 (via C)	*/
	.quad 0x0000000000000000	/* TSS part 2 (via C)	*/
gdt64_end:
.align 64

.type gdt64_ptr, @object
gdt64_ptr:
	.word gdt64_end-gdt64-1
	.quad gdt64

.type mxcsr_ptr, @object
mxcsr_ptr:
	.long 0x1f80			/* Intel SDM power-on default */


#include "pagetable.S"

.code64
.section .text.boot

ENTRY(_libkvmplat_start64)
	cld

	movq %rcx, %rdi
	movq %rdx, %rsi
	call _libkvmplat_efi_setup
	cmpq $0, %rax
	jne fail

	/* load pml4 pointer */
	movl $cpu_pml4, %eax
	movq %eax, %cr3

	lgdt (gdt64_ptr)
	/* let lret jump just one instruction ahead, but set %cs
	 * to the correect GDT entry while doing that.
	 */
	pushq $(gdt64_cs-gdt64)
	pushq $1f
	lretq
1:
	/* Set up the remaining segment registers */
	movq $(gdt64_ds-gdt64), %rax
	movq %rax, %ds
	movq %rax, %es
	movq %rax, %ss
	xorq %rax, %rax
	movq %rax, %fs
	movq %rax, %gs

	/* We will work on cr0 and cr4 multiple times.
	 * We put cr0 into rsi and cr4 into rdi, because cpuid and
	 * xgetbv/xsetbv work on eax/ebx/ecx/edx. */
	movq %cr0, %rsi
	movq %cr4, %rdi
	/* FPU and SSE are part of base x86-64, so no need to check for their
	 * availability before enabling and initializing. */
	andl $(~(X86_CR0_EM | X86_CR0_TS)), %esi
	orl $(X86_CR0_MP | X86_CR0_NE | X86_CR0_WP), %esi
	movq %rsi, %cr0
	fninit
#if __SSE__
	orl $(X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT), %edi
	movq %rdi, %cr4
	ldmxcsr (mxcsr_ptr)
#endif /* __SSE__ */
	/* Check capabilities subject to availability as indicated by cpuid.
	 * First, start off with "standard features" */
	movl $0x1, %eax
	cpuid
#if __AVX__
	/* ecx and edx now contain capability information, so we can now
	 * enable capabilities based on the indicated features */
	/* OSXSAVE needs to be enabled before AVX */
	testl $(X86_CPUID1_ECX_XSAVE), %ecx
	jz noxsave
	orl $(X86_CR4_OSXSAVE), %edi
	movq %rdi, %cr4
	/* now enable AVX. This needs to be last checking cpuid features from
	 * the eax=1 cpuid call, because it clobbers ecx */
	testl $(X86_CPUID1_ECX_AVX), %ecx
	jz noavx
	xorl %ecx, %ecx
	xgetbv
	orl $(X86_XCR0_SSE | X86_XCR0_AVX), %eax
	xsetbv
noavx:
noxsave:
#endif /* __AVX__ */
	/* Now, check for extended features. */
	movl $0x7, %eax
	movl $0x0, %ecx
	cpuid
	/* ebx, ecx, edx now contain extended capabilities information. */
	/* check for and enable FS/GSBASE */
	testl $(X86_CPUID7_EBX_FSGSBASE), %ebx
	jz nofsgsbase
	orl $(X86_CR4_FSGSBASE), %edi
	movq %rdi, %cr4
nofsgsbase:
	/* done setting up CPU capabilities */

	call _libkvmplat_entry

fail:
	cli
	hlt
END(_libkvmplat_start64)

.text
ENTRY(_libkvmplat_newstack)
	movq %rdi, %rsp
	movq %rdx, %rdi

	pushq $0x0
	pushq $0x0

	call *%rsi

	cli
	hlt
END(_libkvmplat_newstack)
