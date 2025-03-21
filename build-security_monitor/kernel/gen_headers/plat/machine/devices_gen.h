/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by <kernel>/tools/hardware/outputs/c_header.py.
 */

#pragma once

#define PHYS_BASE_RAW 0x80000000

#ifndef __ASSEMBLER__

#include <config.h>
#include <mode/hardware.h>  /* for KDEV_BASE */
#include <linker.h>         /* for BOOT_RODATA */
#include <basic_types.h>    /* for p_region_t, kernel_frame_t (arch/types.h) */

/* Wrap raw physBase location constant to give it a symbolic name in C that's
 * visible to verification. This is necessary as there are no real constants
 * in C except enums, and enums constants must fit in an int.
 */
static inline CONST word_t physBase(void)
{
    return PHYS_BASE_RAW;
}

/* INTERRUPTS */
/* KERNEL DEVICES */
#define CLINT_PPTR (KDEV_BASE + 0x0)
#define PLIC_PPTR (KDEV_BASE + 0x200000)

static const kernel_frame_t BOOT_RODATA kernel_device_frames[] = {
    /* /soc/clint@2000000 */
    {
        .paddr = 0x2000000,
        .pptr = CLINT_PPTR,
        .userAvailable = false
    },
    /* /soc/plic@c000000 */
    {
        .paddr = 0xc000000,
        .pptr = PLIC_PPTR,
        .userAvailable = false
    },
    {
        .paddr = 0xc200000,
        /* contains PLIC_PPTR */
        .pptr = KDEV_BASE + 0x400000,
        .userAvailable = false
    },
    {
        .paddr = 0xc400000,
        /* contains PLIC_PPTR */
        .pptr = KDEV_BASE + 0x600000,
        .userAvailable = false
    },
};

/* Elements in kernel_device_frames may be enabled in specific configurations
 * only, but the ARRAY_SIZE() macro will automatically take care of this.
 * However, one corner case remains unsolved where all elements are disabled
 * and this becomes an empty array effectively. Then the C parser used in the
 * formal verification process will fail, because it follows the strict C rules
 * which do not allow empty arrays. Luckily, we have not met this case yet...
 */
#define NUM_KERNEL_DEVICE_FRAMES ARRAY_SIZE(kernel_device_frames)

/* PHYSICAL MEMORY */
static const p_region_t BOOT_RODATA avail_p_regs[] = {
    /* /memory@80000000 */
    {
        .start = 0x80200000,
        .end   = 0x140000000
    },
};

#endif /* !__ASSEMBLER__ */
