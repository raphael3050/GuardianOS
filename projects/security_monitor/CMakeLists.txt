#
# Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

include(settings.cmake)

project(security_monitor C)

find_package(seL4 REQUIRED)
find_package(elfloader-tool REQUIRED)

sel4_import_kernel()

elfloader_import_project()

find_package(musllibc REQUIRED)
find_package(util_libs REQUIRED)
find_package(seL4_libs REQUIRED)

# for the serial driver to use the printf function
add_subdirectory(libsel4serial libsel4serial)
add_subdirectory(libsel4pci libsel4pci)

# This sets up environment build flags and imports musllibc and runtime libraries.
musllibc_setup_build_environment_with_sel4runtime()
sel4_import_libsel4()
util_libs_import_libraries()
sel4_libs_import_libraries()

# Build app_a
add_executable(random_number_generator src/random_number_generator.c)
target_link_libraries(
    random_number_generator 
    sel4runtime 
    sel4serial 
    sel4 
    muslc 
    utils 
    sel4muslcsys 
    sel4platsupport 
    sel4utils 
    sel4debug
    sel4pci
    pci
)


# Build app_b
add_executable(app_b src/app_b.c)
target_link_libraries(
    app_b 
    sel4runtime 
    sel4serial 
    sel4 
    muslc 
    utils 
    sel4muslcsys 
    sel4platsupport 
    sel4utils 
    sel4debug
)


include(cpio)
MakeCPIO(archive.o "$<TARGET_FILE:random_number_generator>;$<TARGET_FILE:app_b>")

add_executable(security_monitor archive.o src/security_monitor.c)
target_link_libraries(
    security_monitor 
    sel4serial 
    sel4pci 
    sel4muslcsys  
    muslc 
    sel4 
    utils 
    pci 
    sel4muslcsys 
    sel4platsupport 
    sel4utils 
    sel4debug 
    sel4allocman
)

include(rootserver)
DeclareRootserver(security_monitor)

if(SIMULATION)
    include(simulation)
    if(KernelSel4ArchX86_64)
        SetSimulationScriptProperty(MEM_SIZE "3G")
    endif()
    if(KernelPlatformQEMUArmVirt)
        SetSimulationScriptProperty(MEM_SIZE "2G")
    endif()
    if(KernelSel4ArchRiscV64)
        SetSimulationScriptProperty(MEM_SIZE "3G")
    endif()
    GenerateSimulateScript()
endif()
