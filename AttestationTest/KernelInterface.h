#ifndef KernelInterface_h
#define KernelInterface_h

#include <mach/mach.h>

extern bool IOSurface_init(void);
extern uint32_t IOSurface_id;
extern mach_port_t IOSurfaceRootUserClient;

extern mach_port_t kernel_task_port;
extern kern_return_t kernel_init(void);
extern kern_return_t kernel_slide_init(void);
extern uint64_t kernel_get_slide(void);
extern uint64_t kernel_get_base(void);
extern uint64_t kernel_read64(uint64_t addr);
extern void kernel_write64(uint64_t addr, uint64_t value);
extern uint64_t kernel_vm_allocate(size_t size);
extern void kernel_vm_deallocate(uint64_t addr, size_t size);

#define KERNEL_MAP_OFFSET 0x8000

extern kern_return_t vm_map_wire(
    vm_map_t map,
    mach_vm_address_t start,
    mach_vm_address_t end,
    vm_prot_t protection,
    boolean_t set_maximum);

#endif 
