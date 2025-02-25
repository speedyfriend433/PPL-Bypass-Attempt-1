#ifndef KernelBridge_h
#define KernelBridge_h

#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include "kernel_memory.h"
#include "kernel.h"
#include "iosurface.h"

#define KERNEL_MAP_OFFSET 0x8000
#define VM_PROT_ALL (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)

#define kernel_read64 kernel_read64
#define kernel_write64 kernel_write64
#define kernel_vm_allocate kernel_vm_allocate
#define kernel_vm_deallocate kernel_vm_deallocate
#define kernel_slide_init kernel_init
#define kernel_get_slide() kernel_slide
#define kernel_get_base() kernel_base_address

extern kern_return_t vm_map_wire(
    vm_map_t map,
    vm_address_t start,
    vm_address_t end,
    vm_prot_t protection,
    boolean_t user_wire
);

#endif
