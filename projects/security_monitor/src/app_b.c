#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <sel4/sel4.h>
#include <sel4utils/process.h>

#include <utils/zf_log.h>
#include <sel4utils/sel4_zf_logif.h>




void send_exit(seL4_CPtr notification_cap){
    // Signal the parent process that the application has completed
    printf("[app-b] : Signaling parent process...\n");
    seL4_Signal(notification_cap);

    printf("[app-a] : Exiting.\n\n");
}


void test_illegal_jump() {
    printf("[TEST] Testing jump memory...\n");
    void (*bad_function)() = (void (*)())0x400000;
    printf("[TEST] Jumping to 0x400000\n");
    bad_function(); 
    printf("[TEST FAILED] Jump successful.\n");
}





int main(int argc, char **argv) {
    printf("\n\n");
    printf("[app-b] : Running... \n");

    /*
        Retrieve the notification capability from argument in order to
        signal the parent process when the application has completed.
    */
    assert(argc > 1 && "Notification capability argument is missing.");
    seL4_CPtr notification_cap = (seL4_CPtr)atoi(argv[1]);
    assert(notification_cap > 0 && "Invalid notification capability.");
    
    // Test illegal memory access
    test_illegal_jump();


    // Exit (send signal to parent process)
    send_exit(notification_cap);
    
    return 0;
}
