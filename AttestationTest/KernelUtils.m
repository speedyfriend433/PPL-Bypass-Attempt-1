#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include "oob_timestamp/mach_vm.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

typedef struct {
    uint64_t next;
    uint64_t prev;
    uint64_t start;
    uint64_t end;
} kernel_map_entry;

static uint64_t kernel_slide = 0;
static uint64_t kernel_base = 0;

uint64_t kernel_get_slide(void) {
    return kernel_slide;
}

uint64_t kernel_get_base(void) {
    return kernel_base;
}

kern_return_t kernel_slide_init(void) {
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header* header = (const struct mach_header*)_dyld_get_image_header(i);
        if (header->filetype == MH_EXECUTE) {
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            mach_vm_address_t base = (mach_vm_address_t)header + slide;
            vm_address_t* possible_kernel_ptr = (vm_address_t*)base;
            for (int j = 0; j < 1024; j++) {
                if ((possible_kernel_ptr[j] & 0xFFFFFFF000000000) == 0xFFFFFFF000000000) {
                    kernel_base = possible_kernel_ptr[j] & ~0xFFF;
                    kernel_slide = kernel_base - 0xFFFFFFF007004000;
                    return KERN_SUCCESS;
                }
            }
        }
    }
    
    mach_port_t kernel_task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (kr != KERN_SUCCESS) {
        return kr;
    }
    
    mach_vm_address_t address = 0xFFFFFFF000000000;
    while (address < 0xFFFFFFF100000000) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_vm_size_t size;
        mach_port_t object_name;
        
        kr = mach_vm_region_recurse(kernel_task,
                           &address,
                           &size,
                           VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info,
                           &info_count);
                           
        if (kr == KERN_SUCCESS && (info.protection & VM_PROT_READ)) {
            kernel_base = address;
            kernel_slide = kernel_base - 0xFFFFFFF007004000; // make it dynamically
            return KERN_SUCCESS;
        }
        
        if (kr != KERN_SUCCESS) break;
        address += size;
    }
    
    return KERN_FAILURE;
}
