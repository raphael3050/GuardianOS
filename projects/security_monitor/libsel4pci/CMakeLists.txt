#
# Author: github:raphael3050
#
# sel4 PCI driver created for GuardianOS project
# 

cmake_minimum_required(VERSION 3.8.2)

add_library(sel4pci STATIC EXCLUDE_FROM_ALL src/pci_utils.c)

target_link_libraries(
    sel4pci
    sel4_autoconf
    sel4runtime
    muslc
    sel4
    sel4platsupport
    sel4muslcsys
    sel4runtime_Config
    sel4allocman
)

target_include_directories(sel4pci PUBLIC include)
