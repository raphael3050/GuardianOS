#include "sel4pci/pci_utils.h"
#include <stdint.h>
#include <stdio.h>
#include <sel4/sel4.h>
#include <sel4platsupport/io.h>
#include <sel4platsupport/platsupport.h>

// Author : raphael3050



void *setup_pci_configuration(vspace_t *vspace, vka_t *vka, ps_io_mapper_t *io_mapper) {
    int error;
    error = sel4platsupport_new_io_mapper(vspace, vka, io_mapper);
    if (error) {
        printf("[-] Failed to initialize IO Mapper.\n");
        return NULL;
    }

    /* map the physical pci configuration base address */
    void *pci_base = ps_io_map(io_mapper, PCI_CONFIG_BASE, 0x100000, false, PS_MEM_NORMAL);
    if (!pci_base) {
        printf("[-] Failed to map PCI configuration space.\n");
        return NULL;
    }

    return pci_base;
}

uintptr_t find_pci_device(void *pci_base, uint16_t target_vendor, uint16_t target_device) {
    printf("[*] Scanning for PCI device (Vendor: 0x%04X, Device: 0x%04X)...\n", target_vendor, target_device);

    for (uint8_t bus = 0; bus < 1; bus++) {
        for (uint8_t slot = 0; slot < 32; slot++) {
            for (uint8_t func = 0; func < 8; func++) {

                uintptr_t pci_config_addr = (uintptr_t)pci_base + (bus << 20) + (slot << 15) + (func << 12);

                uint16_t vendor_id = *((uint16_t *)(pci_config_addr + PCI_VENDOR_ID_OFFSET));
                if (vendor_id == 0xFFFF) continue;

                uint16_t device_id = *((uint16_t *)(pci_config_addr + PCI_DEVICE_ID_OFFSET));

                if (vendor_id == target_vendor && device_id == target_device) {
                    return pci_config_addr;
                }
            }
        }
    }
    return -1;
}

pci_device_info_t configure_pci_device(ps_io_mapper_t *io_mapper, void *pci_base, uint16_t target_vendor, uint16_t target_device, uintptr_t desired_bar0) {
    pci_device_info_t result = {0};

    uintptr_t pci_config_addr = find_pci_device(pci_base, target_vendor, target_device);

    if (pci_config_addr != -1) {
        uint16_t vendor_id = *((uint16_t *)(pci_config_addr + PCI_VENDOR_ID_OFFSET));
        uint16_t device_id = *((uint16_t *)(pci_config_addr + PCI_DEVICE_ID_OFFSET));

        uint32_t bar0 = *((uint32_t *)(pci_config_addr + PCI_BAR0_OFFSET));
        printf("[*] Current BAR0: 0x%08X\n", bar0);

        *((uint32_t *)(pci_config_addr + PCI_BAR0_OFFSET)) = desired_bar0;
        printf("[*] BAR0 set to: 0x%08X\n", desired_bar0);

        void *bar0_vaddr = ps_io_map(io_mapper, desired_bar0, 4096, false, PS_MEM_NORMAL);
        if (!bar0_vaddr) {
            printf("[-] Failed to map BAR0 MMIO region\n");
            return result;
        }

        printf("[+] BAR0 mapped at virtual address: %p\n", bar0_vaddr);

        result.vendor_id = vendor_id;
        result.device_id = device_id;
        result.bar0 = desired_bar0;
        result.bar0_vaddr = bar0_vaddr;
        result.pci_config_addr = pci_config_addr;

        return result;
    }

    printf("[-] No matching PCI device found.\n");
    return result;
}

uint32_t pci_read(pci_device_info_t pci_device_info, uint32_t reg_offset) {
    return *((uint32_t *)(pci_device_info.bar0_vaddr + reg_offset));
}

void pci_write(pci_device_info_t pci_device_info, uint32_t reg_offset, uint32_t value) {
    *((uint32_t *)(pci_device_info.bar0_vaddr + reg_offset)) = value;
}


void add_permission_entry(pci_device_info_t security_oracle, uint32_t source, uint32_t destination, uint8_t permission){
    printf("-----------------------------------------------------\n");
    printf("[*] Adding a new permission to security oracle\n");

    // Déclaration du tableau de permissions
    volatile permission_entry *permissions_table = (permission_entry *)((uintptr_t)security_oracle.bar0_vaddr);

    // Recherche d'une entrée vide (où source est 0)
    for (int i = 0; i < 16; ++i) {
        if (permissions_table[i].source == 0xFF) {  // Vérifie si l'entrée est vide
            // Remplissage des champs de la structure
            permissions_table[i].source = source;           // Source dans le champ source
            permissions_table[i].destination = destination; // Destination dans le champ destination
            permissions_table[i].permission = permission;   // Permission dans le champ permission

            printf("[*] Permission insérée : source=0x%08x, destination=0x%08x, permission=0x%02x\n", 
                   source, destination, permission);
            printf("-----------------------------------------------------\n");
            return;
        }
    }

    printf("[!] Table des permissions pleine, impossible d'insérer.\n");
    printf("-----------------------------------------------------\n");
}



