#include "common.h"

unsigned long bits_clear_set_mask(unsigned long val, unsigned long new,
				  unsigned long mask)
{
	val &= ~mask;
	val |= new & mask;
	return val;
}

unsigned long bits_or_mask(unsigned long a, unsigned long mask_a,
			   unsigned long b, unsigned long mask_b)
{
	return (a & mask_a) | (b & mask_b);
}
