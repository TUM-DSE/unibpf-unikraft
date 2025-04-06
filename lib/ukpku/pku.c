#include "uk/plat/paging.h"
#include <uk/assert.h>
#include <uk/print.h>
#include <uk/atomic.h>
#include <uk/arch/limits.h>
#include <uk/pku.h>
#include <uk/pkru.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>

#define PKEY_MASK (~(PAGE_PROT_PKEY0 | PAGE_PROT_PKEY1 | PAGE_PROT_PKEY2 | \
						PAGE_PROT_PKEY3))
#define CLEAR_PKEY(prot)		(prot & PKEY_MASK)
#define INSTALL_PKEY(prot, pkey)	(prot | pkey)

#define MAX_PKEYS	16

#define VALID_PROT_MASK	(PROT_READ | PROT_WRITE | PROT_EXEC)

#define size_to_num_pages(size) \
	(ALIGN_UP((unsigned long)(size), __PAGE_SIZE) / __PAGE_SIZE)

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

	for (i = 1; i< MAX_PKEYS; i++) {
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

int pkey_set_perm(int prot, int key)
{
	uint32_t pkru_val = 0;

	if (unlikely((prot & ~VALID_PROT_MASK) && (prot & ~PROT_NONE))) {
		errno = -EINVAL;
		return -1;
	}

	pkru_val = rdpkru();
	if (prot == PROT_NONE) {
		pkru_val |= 1UL << (key * 2);
		pkru_val |= 1UL << ((key * 2) + 1);
		goto write_pkru;
	}
	if (prot & PROT_READ) {
		pkru_val &= ~(1UL << (key * 2));
		pkru_val |= 1UL << ((key*2) + 1);
	}
	if (prot & PROT_WRITE) {
		pkru_val &= ~(1UL << (key*2));
		pkru_val &= ~(1UL << ((key*2) + 1));
	}

write_pkru:
	wrpkru(pkru_val);

	return 0;
}

int pkey_mprotect(void *addr, size_t len, int prot, int key)
{
	bool in_use = 0;
	struct uk_pagetable *pt = ukplat_pt_get_active();
	int rc = 0;
	unsigned long pgs = 0;
	/* With the current unikraft API, we can not get current prot, hence
	 * the pkey_mprotect() caller has to supply one.
	 */
	unsigned long attr = prot;
	unsigned long pbkey = 0;

	if (unlikely(len == 0)) {
		errno = -EINVAL;
		return -1;
	}

	/* len will overflow when aligning it to page size */
	if (unlikely(len > __SZ_MAX - PAGE_SIZE)) {
		errno = -ENOMEM;
		return -1;
	}

	if (unlikely((prot & ~VALID_PROT_MASK) && (prot & ~PROT_NONE))) {
		errno = -EINVAL;
		return -1;
	}

	if (key < 0 || key >= MAX_PKEYS) {
		errno = -EINVAL;
		return -1;
	}

	in_use = uk_load_n(&pkeys[key]);
	if (in_use == 0) {
		errno = -EINVAL;
		return -1;
	}

	if (key & 0x01) {
		pbkey |= PAGE_PROT_PKEY0;
	}
	if (key & 0x02) {
		pbkey |= PAGE_PROT_PKEY1;
	}
	if (key & 0x04) {
		pbkey |= PAGE_PROT_PKEY2;
	}
	if (key & 0x08) {
		pbkey |= PAGE_PROT_PKEY3;
	}

	/* clear current pkey */
	attr = CLEAR_PKEY(attr);
	/* install new pkey */
	attr = INSTALL_PKEY(attr, pbkey);
	pgs = size_to_num_pages(len);;
	rc = ukplat_page_set_attr(pt, (__vaddr_t)addr, pgs, attr, 0);
	if (rc < 0)
		return rc;

	return rc;
}
