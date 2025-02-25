#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include "oob_timestamp/mach_vm.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>

typedef struct {
    uint64_t magic;
    uint64_t flags;
    uint64_t address;
    uint64_t size;
} iosurface_map_entry;

static uint64_t kernel_slide = 0;
static uint64_t kernel_base = 0;

uint64_t kernel_get_slide(void) {
    return kernel_slide;
}

uint64_t kernel_get_base(void) {
    return kernel_base;
}

kern_return_t kernel_slide_init(void) {
    mach_port_t self_task = mach_task_self();
    vm_address_t scan_addr = 0x100000000;
    vm_size_t scan_size = 0x100000000;
    
    while (scan_addr < 0x200000000) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_vm_size_t size;
        mach_port_t object_name;
        vm_address_t address = scan_addr;
        
        kern_return_t kr = vm_region_64(self_task,
                                      &address,
                                      &size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info,
                                      &count,
                                      &object_name);
        
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) &&
            (info.protection & VM_PROT_WRITE)) {
            for (vm_address_t ptr = address;
                 ptr < (address + size - sizeof(uint64_t));
                 ptr += sizeof(uint64_t)) {
                uint64_t value;
                if (vm_read_overwrite(self_task, ptr, sizeof(uint64_t),
                                    (vm_address_t)&value, &size) == KERN_SUCCESS) {
                    if ((value & 0xFFFFFFF000000000) == 0xFFFFFFF000000000) {
                        kernel_base = value & ~0xFFF;
                        kernel_slide = kernel_base - 0xFFFFFFF007004000;
                        return KERN_SUCCESS;
                    }
                }
            }
        }
        
        scan_addr = address + size;
    }
    
    return KERN_FAILURE;
}
