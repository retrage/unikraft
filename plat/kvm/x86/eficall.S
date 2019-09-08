/* SPDX-License-Identifier: MIT */

.global efi_call1
.global efi_call2
.global efi_call3
.global efi_call4

.text

efi_call1:
  movq %rsi, %rcx
  call *%rdi
  ret

efi_call2:
  movq %rsi, %rcx
  movq %rdx, %rdx
  call *%rdi
  ret

efi_call3:
  movq %rcx, %r10
  movq %rsi, %rcx
  movq %rdx, %rdx
  movq %r10, %r8
  call *%rdi
  ret

efi_call4:
  movq %rcx, %r10
  movq %r8, %r11
  movq %rsi, %rcx
  movq %rdx, %rdx
  movq %r10, %r8
  movq %r11, %r9
  call *%rdi
  ret
