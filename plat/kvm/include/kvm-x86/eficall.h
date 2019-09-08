/* SPDX-License-Identifier: MIT */

#ifndef EFICALL_H_
#define EFICALL_H_

int efi_call1(void *func, void *arg1);
int efi_call2(void *func, void *arg1, void *arg2);
int efi_call3(void *func, void *arg1, void *arg2, void *arg3);
int efi_call4(void *func, void *arg1, void *arg2, void *arg3, void *arg4);

#endif /* EFICALL_H_ */
