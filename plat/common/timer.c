#include <uk/alloc.h>
#include <uk/assert.h>
#include <timer.h>

static struct uk_alloc *allocator;

int ukplat_timer_callback_register(timer_callback_func_t func, void *arg)
{
	struct callback_handler *h;

        /* New handler */
        h = uk_malloc(allocator, sizeof(struct callback_handler));
        if (!h)
        	return -ENOMEM;
        h->func = func;
        h->arg = arg;

        UK_SLIST_INSERT_HEAD(&callback_handlers, h, entries);

        return 0;
}

int ukplat_timer_callback_init(struct uk_alloc *a)
{
	UK_ASSERT(!allocator);

        allocator = a;
        
        /* Clear list head */
        UK_SLIST_INIT(&callback_handlers);

        return 0;
}
