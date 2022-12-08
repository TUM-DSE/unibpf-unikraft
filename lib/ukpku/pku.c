#include "uk/plat/paging.h"
#include <uk/assert.h>
#include <uk/print.h>
#include <uk/atomic.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include <uk/pku.h>

#define MAX_PKEYS	16

static bool pkeys[MAX_PKEYS] = { 0 };

int pkey_alloc(unsigned int flags, unsigned int init_rights)
{
	int i = 0;

	/* No flags supported yet. */
	if (flags) {
		errno =  -EINVAL;
		return -1;
	}
	/* check for unsupported init values */
	if (init_rights & ~PKEY_ACCESS_MASK) {
		errno =  -EINVAL;
		return -1;
	}

	for (i = 0; i< MAX_PKEYS; i++) {
		if (uk_compare_exchange_sync(&pkeys[i], 0, 1) == 1)
			return i;
	}

	errno = -ENOSPC;
	return -1;
}

int pkey_free(int pkey)
{
	if (pkey < 0 || pkey >= MAX_PKEYS) {
		errno = -EINVAL;
		return -1;
	}

	if (uk_compare_exchange_sync(&pkeys[pkey], 1, 0) == 0) {
		return 0;
	} else {
		errno = -EINVAL;
		return -1;
	}
}

int pkey_mprotect(void *addr, size_t len, int prot, int pkey)
{
	return 0;
}
