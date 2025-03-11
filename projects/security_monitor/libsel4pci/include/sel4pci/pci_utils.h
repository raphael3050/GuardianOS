#ifndef PCI_UTILS_H
#define PCI_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <sel4utils/vspace.h>
#include <sel4platsupport/io.h>

/*==============================*/
// GuardianOS - PCI Utils
// Author: AZOU R.
/*==============================*/


/*
* Base address of the PCI configuration space
* See QEMU hw/riscv/virt.c for details
*/
#define PCI_CONFIG_BASE  0x30000000 


/*
* Base address of the PCI physical memory
* See QEMU hw/riscv/virt.c for details
* 0x40000000-0x80000000 is reserved for mmio devices
*/
#define PCI_PHYSICAL_BASE 0x40000000

/*
* PCI configuration space offsets
* See https://wiki.osdev.org/PCI
*/
#define PCI_VENDOR_ID_OFFSET  0x00
#define PCI_DEVICE_ID_OFFSET  0x02
#define PCI_BAR0_OFFSET       0x10

typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    uint32_t bar0;
    void *bar0_vaddr;
    uintptr_t pci_config_addr;
} pci_device_info_t;



typedef struct {
    uint32_t source;        // Identifiant de la source (thread_id ou device_id)
    uint32_t destination;   // Identifiant de la destination (device_id)
    uint8_t permission;     // Permission (NONE ou FULL)
} permission_entry;

/*
* Map the PCI base configuration address in virtual memory
*
* @param vspace: the virtual memory space
* @param vka: the VKA allocator
* @param io_mapper: the IO mapper
*/
void *setup_pci_configuration(vspace_t *vspace, vka_t *vka, ps_io_mapper_t *io_mapper);


/*
* Find a PCI device in the PCI configuration space
*
* @param pci_base: the base address of the PCI configuration space
* @param target_vendor: the target vendor ID
* @param target_device: the target device ID
* @return the configuration address of the PCI device
*/
uintptr_t find_pci_device(void *pci_base, uint16_t target_vendor, uint16_t target_device);



/*
* Configure a PCI device
*
* @param io_mapper: the IO mapper
* @param pci_base: the base address of the PCI configuration space
* @param target_vendor: the target vendor ID
* @param target_device: the target device ID
* @param desired_bar0: the desired physical address for BAR0
* @return the PCI configured device information
*/
pci_device_info_t configure_pci_device(ps_io_mapper_t *io_mapper, void *pci_base, uint16_t target_vendor, uint16_t target_device, uintptr_t desired_bar0);


// fonction pour lire un registre d'un périphérique PCI
uint32_t pci_read(pci_device_info_t pci_device_info, uint32_t reg_offset);

// fonction pour écrire un registre d'un périphérique PCI
void pci_write(pci_device_info_t pci_device_info, uint32_t reg_offset, uint32_t value);

void setup_ips_pci(ps_io_mapper_t *io_mapper, void *pci_base);

// fonction pour ajouter une entrée de permission dans le security oracle
//void add_permission_entry(pci_device_info_t pci_device_info, uint8_t thread_id, uint8_t permission);

void add_permission_entry(pci_device_info_t device_info, uint32_t source, uint32_t destination, uint8_t permission);

#endif // PCI_UTILS_H
