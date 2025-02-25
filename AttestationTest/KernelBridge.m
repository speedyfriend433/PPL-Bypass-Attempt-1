#import "KernelBridge.h"
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <IOKit/IOKitLib.h>
#import "kernel.h"
#import "kernel_memory.h"

extern mach_port_t kernel_task_port;
extern uint32_t IOSurface_id;
extern io_connect_t IOSurfaceRootUserClient;

kern_return_t vm_map_wire(
    vm_map_t map,
    vm_address_t start,
    vm_address_t end,
    vm_prot_t protection,
    boolean_t user_wire
) {
    kern_return_t kr;
    kr = vm_protect(map, start, end - start, FALSE, protection);
    if (kr != KERN_SUCCESS) {
        return kr;
    }
    
    mach_port_t host_priv;
    kr = host_get_host_priv_port(mach_host_self(), &host_priv);
    if (kr != KERN_SUCCESS) {
        return kr;
    }
    
    return vm_wire(host_priv, map, start, end - start, protection);
}
