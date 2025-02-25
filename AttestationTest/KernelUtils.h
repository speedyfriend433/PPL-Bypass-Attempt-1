#ifndef KernelUtils_h
#define KernelUtils_h

#include <mach/mach.h>

uint64_t kernel_get_slide(void);
uint64_t kernel_get_base(void);
kern_return_t kernel_slide_init(void);

#endif 
