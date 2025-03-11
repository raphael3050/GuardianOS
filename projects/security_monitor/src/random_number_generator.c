#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <sel4/sel4.h>

void send_exit(seL4_CPtr notification_cap) {
    printf("[rng] : Signaling parent process...\n");
    seL4_Signal(notification_cap);
    printf("[rng] : Exiting.\n\n");
}

void print_caps(seL4_CPtr cnode) {
    for (seL4_CPtr slot = 2; slot < 255; slot++) {  // Scanner les slots connus
        seL4_Word cap_type = seL4_DebugCapIdentify(slot);
        printf("Found untyped cap of type %d at slot %d\n", cap_type, slot);
    }
}

int new_thread(void *arg1, void *arg2, void *arg3) {
    printf("Hello2: arg1 %p, arg2 %p, arg3 %p\n", arg1, arg2, arg3);
    void (*func)(int) = arg1;
    func(*(int *)arg2);
    while(1);
}


int main(int argc, char **argv) {
    printf("\n\n[rng] : Running... \n");

    assert(argc > 2 && "Missing arguments: expected notification cap and BAR0 virtual address.");

    // Retrieve the notification capability
    seL4_CPtr notification_cap = (seL4_CPtr)atoi(argv[1]);
    assert(notification_cap > 0 && "Invalid notification capability.");

    // Retrieve the BAR0 mapped virtual address
    volatile uint32_t *bar0_vaddr = (volatile uint32_t *)(uintptr_t)atoi(argv[2]);
    assert(bar0_vaddr != NULL && "Invalid BAR0 virtual address.");

    printf("[rng] : BAR0 mapped at vaddr: %p\n", (void *)bar0_vaddr);

    // Test read from BAR0
    uint32_t bar0_value = bar0_vaddr[0];  // Read first 4 bytes
    printf("[rng] : Read from BAR0: 0x%08x\n", bar0_value);


    //print_caps(seL4_CapInitThreadCNode);
    //seL4_CPtr child_untyped = find_untyped_cap(seL4_CapInitThreadCNode);
    //seL4_CPtr child_tcb = child_untyped + 1;
    //seL4_Untyped_Retype(child_untyped, seL4_TCBObject, 0, seL4_CapInitThreadCNode, 0, 0, child_tcb, 1);
    send_exit(notification_cap);

    return 0;
}
