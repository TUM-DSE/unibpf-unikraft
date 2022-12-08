#ifndef __PKU__
#define __PKU__

#include <stddef.h>

#define PKEY_DISABLE_ACCESS 0x1
#define PKEY_DISABLE_WRITE 0x2
#define PKEY_ACCESS_MASK (PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)

int pkey_alloc(unsigned int flags, unsigned int access_rights);
int pkey_free(int pkey);
int pkey_mprotect(void *addr, size_t len, int prot, int pkey);

#endif /* __PKU__ */
