#ifndef __PLAT_CMN_TIMER_H__
#define __PLAT_CMN_TIMER_H__

#include <uk/list.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes timer subsystem
 * @param a The allocator to be used for internal memory allocations
 * @return initialization status
 */
int ukplat_timer_callback_init(struct uk_alloc *a);

typedef void (*timer_callback_func_t)(void *);

struct callback_handler {
	timer_callback_func_t func;
        void *arg;

        UK_SLIST_ENTRY(struct callback_handler) entries;
};

UK_SLIST_HEAD(callback_handler_head, struct callback_handler);
struct callback_handler_head callback_handlers;

/**
 * Registers a timer callback function
 * @param func Callback function
 * @param arg Extra argument to be handover to callback function
 * @return 0 on success, a negative errno value on errors
 */
int ukplat_timer_callback_register(timer_callback_func_t func, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* __PLAT_CMN_TIMER_H__ */
