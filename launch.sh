#!/bin/sh

rm -r build-security_monitor/*
cd build-security_monitor || exit
../security_monitor/init-build.sh -DPLATFORM=qemu-riscv-virt \
    -DCMAKE_C_FLAGS="-march=rv64imac -mabi=lp64" \
    -DSIMULATION=TRUE \
    -DOPENSBI_PATH="/host/tools/opensbi"
ninja || exit
./simulate --extra-qemu-args="-bios none -device security_oracle -device crypto_device -device my_ip"