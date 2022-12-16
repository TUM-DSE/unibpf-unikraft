#ifndef __PKRU__
#define __PKRU__

#include <stdint.h>

/* Low level C wrapper for WRPKRU
 */
__attribute__((always_inline)) static inline void wrpkru(uint32_t val)
{
	asm volatile (  "mov %0, %%eax;"
			"xor %%ecx, %%ecx;"
			"xor %%edx, %%edx;"
			"wrpkru;"
			:: "r"(val) : "eax", "ecx", "edx");
}

/* Low level C wrapper for RDPKRU: return the current protection key or
 *  * -ENOSPC if the CPU does not support PKU */
__attribute__((always_inline)) static inline uint32_t rdpkru(void)
{
	uint32_t res;

	asm volatile (  "xor %%ecx, %%ecx;"
			"rdpkru;"
			"movl %%eax, %0" : "=r"(res) :: "rax", "rdx", "ecx");

	return res;
}
#endif /* __PKRU__ */
