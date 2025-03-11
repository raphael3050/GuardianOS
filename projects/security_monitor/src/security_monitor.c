#include <stdio.h>
#include <sel4/sel4.h>
#include <sel4platsupport/bootinfo.h>
#include <utils/util.h>
#include <sel4utils/process.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <vka/object.h>
#include <vka/vka.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>
#include <simple/simple.h>
#include <simple-default/simple-default.h>
#include <sel4platsupport/platsupport.h>
#include <pci/pci.h>
#include <sel4platsupport/io.h>
#include <sel4pci/pci_utils.h>

/*-------------------------------------------------------------------------------------------------*/
/* Constants */
#define EP_BADGE 0x61 // Badge arbitraire pour les notifications
#define APP_PRIORITY seL4_MaxPrio

#define ALLOCATOR_STATIC_POOL_SIZE (BIT(seL4_PageBits) * 10)
#define ALLOCATOR_VIRTUAL_POOL_SIZE (BIT(seL4_PageBits) * 100)

/* mémoire statique pour l'allocateur */
static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];
UNUSED static sel4utils_alloc_data_t data;

/* Global variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;
vspace_t vspace;
ps_io_mapper_t io_mapper;
vka_object_t fault_ep; 

static uint32_t global_app_id = 1;

/* Table de management des apps */
typedef struct {
    const char *app_name; // Application name
    int is_trusted;       // 1 if trusted, 0 if untrusted
    uint32_t app_id;      // world ID
} AppTrustConfig;

typedef struct {
    const char *ip_name;    // Application name
    uint16_t target_vendor; // Vendor ID
    uint16_t target_device; // Device ID
    int is_trusted;         // 1 if trusted, 0 if untrusted
} IPTrustConfig;


AppTrustConfig app_trust_table[] = {
    {"random_number_generator", 1, 0},
    {"app_b", 0, 0}
};

IPTrustConfig ip_trust_table[] = {
    {"security_oracle", 0x1d0f, 0x1235, 1},
    {"my_ip", 0x1234, 0xcafe, 1},
    {"crypto_device", 0x1234, 0xbeef, 0}
};

#define APP_TRUST_TABLE_SIZE (sizeof(app_trust_table) / sizeof(AppTrustConfig))

/*-------------------------------------------------------------------------------------------------*/

void init_message(void) {
    printf("---------------------------------------------------------------\n");
    printf("   ______                     ___             ____  _____\n");
    printf("  / ____/_  ______ __________/ (_)___ _____  / __ \\/ ___/\n");
    printf(" / / __/ / / / __ `/ ___/ __  / / __ `/ __ \\/ / / /\\__ \\\n");
    printf("/ /_/ / /_/ / /_/ / /  / /_/ / / /_/ / / / / /_/ /___/ / \n");
    printf("\\____/\\__,_/\\__,_/_/   \\__,_/_/\\__,_/_/ /_/\\____//____/  \n\n");
    printf("Author: raphael3050\n");
}

int is_trusted_app(const char *app_name) {
    for (size_t i = 0; i < APP_TRUST_TABLE_SIZE; i++) {
        if (strcmp(app_trust_table[i].app_name, app_name) == 0) {
            return app_trust_table[i].is_trusted;
        }
    }
    printf("[-] App '%s' not found in the trust table, setting to untrusted\n", app_name);
    return 0;
}


//---------------------------------------------------------------------------------------------

void fault_handler(void) {
    while (1) {
        seL4_Word sender_badge = 0;
        seL4_MessageInfo_t tag = seL4_Recv(fault_ep.cptr, &sender_badge);

        printf("[FAULT HANDLER] Received fault! IPC Label: %d\n", seL4_MessageInfo_get_label(tag));
        printf("[FAULT HANDLER] Fault from thread with badge: %lu\n", sender_badge);

        // Récupérer et afficher l'adresse fautive
        seL4_Word fault_address = seL4_GetMR(0);
        printf("[FAULT HANDLER] Faulting address: 0x%lx\n", fault_address);

        // Identifier le type de faute
        int fault_type = seL4_MessageInfo_get_label(tag);
        if (fault_type == seL4_Fault_VMFault) {
            printf("[FAULT HANDLER] Detected a VM Fault!\n");
        } else if (fault_type == seL4_Fault_UnknownSyscall) {
            printf("[FAULT HANDLER] Detected an Unknown Syscall Fault!\n");
        } else if (fault_type == seL4_Fault_UserException) {
            printf("[FAULT HANDLER] Detected a User Exception!\n");
        } else if (fault_type == seL4_Fault_CapFault) {
            printf("[FAULT HANDLER] Detected a Cap Fault!\n");
        } else {
            printf("[FAULT HANDLER] Unknown fault type: %d\n", fault_type);
        }

        // Le thread fautif peut être suspendu ou continuer son exécution
        // https://docs.sel4.systems/Tutorials/fault-handlers.html
    }
}
//---------------------------------------------------------------------------------------------

/*
* Associe un ID aux applications déclarées dans le tableau app_trust_table
* 
* Le bit de poids faible est utilisé pour distinguer les applications de confiance des applications non fiables
* Les applications de confiance ont un bit de poids faible à 1, tandis que les applications non fiables ont un bit de poids faible à 0
* Ce distinction n'est pas utilisée dans seL4 mais peut être utile pour la gestion des permissions dans TrustSoC
*/
void setup_app_ids(void) {
    for (size_t i = 0; i < APP_TRUST_TABLE_SIZE; i++) {
        uint32_t app_id = global_app_id++;
        if (app_trust_table[i].is_trusted) {
            // Set app ID for trusted apps
            app_trust_table[i].app_id = (app_id << 1) | 1;
        }else{
            // Set app ID for untrusted apps
            app_trust_table[i].app_id = (app_id << 1) | 0;
        }
    }
}


//---------------------------------------------------------------------------------------------
/*
* Configuration et lancement d'une application
* Le paramètre pci_device_info contient les informations sur une IP 
* Il faudrait revoir la signature de la méthode pour pouvoir prendre en compte plusieurs IPs ou aucune IP
*/
void spawn_process(AppTrustConfig* app_config, pci_device_info_t pci_device_info) {
    int error = 0;
    bool is_trusted = is_trusted_app(app_config->app_name);

    printf("[*] Spawning process: %s - %s\n", app_config->app_name, is_trusted ? "trusted" : "untrusted");

    // Configure process
    sel4utils_process_t new_process;
    sel4utils_process_config_t config = process_config_default_simple(&simple, app_config->app_name, APP_PRIORITY);

    config.fault_endpoint = fault_ep;
    config.create_fault_endpoint = false;
    config.p_world_id = app_config->app_id;
    vka_object_t new_cspace = {0}, new_vspace = {0};

    // Allocate CSpace and VSpace for untrusted apps
    if (!is_trusted) {
        if ((error = vka_alloc_cnode_object(&vka, CONFIG_SEL4UTILS_CSPACE_SIZE_BITS, &new_cspace))) {
            ZF_LOGF("Failed to allocate new CSpace for untrusted app.");
        }
    
        if ((error = vka_alloc_page_directory(&vka, &new_vspace))) {
            ZF_LOGF("Failed to allocate new VSpace for untrusted app.");
        }
    
        config.cnode = new_cspace;
        config.page_dir = new_vspace;
    } else {
        config.create_cspace = true;
        config.create_vspace = true;
    }

    printf("[*] Created p_world_id: 0b");
    for (int i = 31; i >= 0; i--) {
        printf("%d", (config.p_world_id >> i) & 1);
    }
    printf("\n");
    // Configuration du process avec la structure config
    if ((error = sel4utils_configure_process_custom(&new_process, &vka, &vspace, config))) {
        ZF_LOGF("Failed to configure process '%s'.", app_config->app_name);
    }

    // Alloue un objet de notification pour que l'application puisse notifier la root task
    vka_object_t notification_object;
    if ((error = vka_alloc_notification(&vka, &notification_object))) {
        ZF_LOGF("Failed to allocate notification object.");
    }

    // Creation d'une capability badgée pour la notification
    cspacepath_t notification_path;
    vka_cspace_make_path(&vka, notification_object.cptr, &notification_path);
    seL4_CPtr notification_cap = sel4utils_mint_cap_to_process(&new_process, notification_path, seL4_AllRights, EP_BADGE);
    if (notification_cap == 0) {
        ZF_LOGF("Failed to mint a badged notification cap.");
    }

    seL4_CPtr bar0_frame_cap = seL4_CapNull;
    void *child_bar0_vaddr = NULL;
    if (is_trusted) {
        /*
        * Si l'application est de confiance, on peut lui passer des capabilities
        * Ici, on passe la capability du frame BAR0 pour que l'application puisse y accéder
        * Sans cette capability, l'application ne peut pas accéder à l'IP
        */

        reservation_t bar0_reservation = vspace_reserve_range(&new_process.vspace, seL4_PageBits, seL4_AllRights, 1, &child_bar0_vaddr);
        if (!bar0_reservation.res) {
            ZF_LOGF("Failed to reserve range in child process.");
        }

        bar0_frame_cap = vspace_get_cap(&vspace, pci_device_info.bar0_vaddr);
        if (bar0_frame_cap == seL4_CapNull) {
            ZF_LOGF("Failed to get cap for BAR0 frame.");
        }
        
        vka_object_t bar0_dup_cap;
        if ((error = vka_cspace_alloc(&vka, &bar0_dup_cap.cptr))) {
            ZF_LOGF("Failed to allocate cspace slot for BAR0 duplicate.");
        }

        // Copie de la capability du frame BAR0 dans le CSpace de l'application
        if ((error = seL4_CNode_Copy(
                seL4_CapInitThreadCNode, bar0_dup_cap.cptr, seL4_WordBits,
                seL4_CapInitThreadCNode, bar0_frame_cap, seL4_WordBits, seL4_AllRights))) {
            ZF_LOGF("Failed to copy BAR0 frame cap.");
        }

        // Map du frame BAR0 dans l'espace d'adressage de l'application
        if ((error = sel4utils_map_page(
                &vka, new_process.pd.cptr, bar0_dup_cap.cptr, child_bar0_vaddr,
                seL4_AllRights, 1, NULL, NULL))) {
            ZF_LOGF("Failed to map BAR0 frame into child process.");
        }
    }

    /* Arguments pour le process */
    char notification_arg[16], bar0_vaddr_arg[16];
    snprintf(notification_arg, sizeof(notification_arg), "%u", notification_cap);
    snprintf(bar0_vaddr_arg, sizeof(bar0_vaddr_arg), "%u", is_trusted ? (uintptr_t)child_bar0_vaddr : 0);

    const char *app_args[] = {app_config->app_name, notification_arg, bar0_vaddr_arg};
    if ((error = sel4utils_spawn_process_v(&new_process, &vka, &vspace, 3, (char **)app_args, 1))) {
        ZF_LOGF("Failed to spawn process: %s", app_config->app_name);
    }

    // Attendre que le processus notifie la root task de sa terminaison
    printf("[*] Waiting for notification from '%s'...\n", app_config->app_name);
    seL4_Wait(notification_object.cptr, NULL);
    printf("[*] Notification received from '%s'.\n", app_config->app_name);

    /* Cleanup */
    sel4utils_destroy_process(&new_process, &vka);
    vka_free_object(&vka, &notification_object);

    if (!is_trusted) {
        vka_free_object(&vka, &new_vspace);
        vka_free_object(&vka, &new_cspace);
    }
}



int main(void) {
    init_message();
    printf("[*] Security monitor (rootserver) is running...\n");

    // Bootinfo et initialisation des ressources
    info = platsupport_get_bootinfo();
    simple_default_init_bootinfo(&simple, info);
    simple_print(&simple);

    // Initialisation de l'allocateur de mémoire
    allocman = bootstrap_use_current_simple(&simple, ALLOCATOR_STATIC_POOL_SIZE, allocator_mem_pool);
    allocman_make_vka(&vka, allocman);

    // Initialisation du VSpace et du pool de mémoire virtuelle
    sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace, &data, simple_get_pd(&simple), &vka, info);
    void *vaddr;
    reservation_t virtual_reservation = vspace_reserve_range(&vspace, ALLOCATOR_VIRTUAL_POOL_SIZE, seL4_AllRights, 1, &vaddr);
    if (!virtual_reservation.res || vaddr == NULL) {
        ZF_LOGF("Failed to reserve virtual memory range.");
    }
    bootstrap_configure_virtual_pool(allocman, vaddr, ALLOCATOR_VIRTUAL_POOL_SIZE, simple_get_pd(&simple));
    //-------------------------------------------------------------------------------------------------

    // Initialisation des IDs des applications
    setup_app_ids();

    //-------------------------------------------------------------------------------------------------
    // addresse de base de la configuration PCI
    void* pci_base_config_addr = setup_pci_configuration(&vspace, &vka, &io_mapper);
    if (!pci_base_config_addr) {
        ZF_LOGF("Failed to setup PCI MMIO region.");
    }
    
    // Chaque device PCI obtient une adresse physique et celle-ci est mappée dans l'espace d'adressage de la root task
    pci_device_info_t security_oracle_info = configure_pci_device(&io_mapper, pci_base_config_addr, 0x1d0f, 0x1235, 0x40000000);
    printf("[*] PCI device configured at: 0x%lx\n", security_oracle_info.pci_config_addr);

    pci_device_info_t rng_ip_info = configure_pci_device(&io_mapper, pci_base_config_addr, 0x1234, 0xcafe, 0x50000000);
    printf("[*] PCI device configured at: 0x%lx\n", rng_ip_info.pci_config_addr);
    
    pci_device_info_t crypto_device_info = configure_pci_device(&io_mapper, pci_base_config_addr, 0x1234, 0xbeef, 0x60000000);
    printf("[*] PCI device configured at: 0x%lx\n", crypto_device_info.pci_config_addr);


    add_permission_entry(security_oracle_info, 1, 0xcafe, 0x01); // La root task s'accorder elle-même l'accès à l'IP
    add_permission_entry(security_oracle_info, 0xcafe, 0xbeef, 0x01);
    add_permission_entry(security_oracle_info, 0xcafe, 0x1235, 0x01);
    add_permission_entry(security_oracle_info, app_trust_table[0].app_id, 0xcafe, 0x01);
    add_permission_entry(security_oracle_info, app_trust_table[1].app_id, 0x1235, 0x00); 
    
    // Test de l'IP RNG
    uint32_t seed = 0x12345678;
    pci_write(rng_ip_info, 0x04, seed);
    uint32_t random_value = pci_read(rng_ip_info, 0x00);
    printf("[*] Random value read from PCI device: 0x%08X\n", random_value);



    //-------------------------------------------------------------------------------------------------
    // Lancement du gestionnaire de fautes dans un thread séparé
    sel4utils_thread_t fault_thread;
    uint32_t fault_ep_world_id=1;
    int error = vka_alloc_endpoint(&vka, &fault_ep);
    if (error != 0) {
        ZF_LOGF("Failed to allocate fault endpoint.");
    }
    error = sel4utils_configure_thread(&vka, &vspace, &vspace, fault_ep.cptr,
        seL4_CapInitThreadCNode, seL4_NilData, &fault_thread, fault_ep_world_id);
    if (error) {
        ZF_LOGF("Failed to configure fault handler thread.");
    }
    printf("[*] Fault thread configured.\n");
    error = sel4utils_start_thread(&fault_thread, (sel4utils_thread_entry_fn)fault_handler,
                               NULL, NULL, 1);
    if (error) {
        ZF_LOGF("Failed to start fault handler thread.");
    }
    printf("[*] Fault handler started.\n");

    //-------------------------------------------------------------------------------------------------

    // Spawn des processus (donne accès à l'IP RNG si l'application est de confiance)
    spawn_process(&app_trust_table[0], rng_ip_info);
    spawn_process(&app_trust_table[1], rng_ip_info);

    
    // Nettoyage et suspension
    vspace_free_reservation(&vspace, virtual_reservation);
    printf("[*] Security monitor completed, suspending...\n");
    seL4_TCB_Suspend(seL4_CapInitThreadTCB);
    ZF_LOGF("Failed to suspend the security monitor thread\n");
    return 0;
}


