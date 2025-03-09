#!/bin/sh

rm /usr/bin/qemu-system-riscv64 || exit
cp qemu/build/qemu-system-riscv64 /usr/bin/ || exit
chmod +x /usr/bin/qemu-system-riscv64 || exit