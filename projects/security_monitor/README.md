# GuardianOS 


This repository contains the security monitor (i.e the root task created at the sel4 boot). The role of the security monitor is to create the differents applications marked as trusted / untrusted and to manage the communication between them. Each trusted application is created in a dedicated address space and the communication between them is done through the seL4 IPC mechanism. The security monitor is also responsible for the creation of the different capabilities and the management of the access rights of each application.


## Setup

First clone a fresh copy of the sel4 microkernel and the sel4 projects repository. Then clone this repository in the projects directory of the sel4 projects repository.

```bash
todo: give details on how to clone the sel4 microkernel and the sel4 projects repository
```

### QEMU

This project use an updated version of QEMU that support the RISCV CSR register $0x5c0$ which is used to store the current execution context id $world\_id$. To update QEMU to support that, you just need to apply the patch located in the tools directory of this repository. 

```bash
cd /sel4-guardianos/qemu
git apply /path/to/security_monitor/tools/qemu_riscv_csr.patch
```

Then build QEMU as usual.

```bash
./configure --target-list=riscv64-softmmu
make -j(nproc)
```




## Build

Go to the root of the sel4 projects repository and run the following command:

```bash
cd projects/
mkdir security_monitor
# link the files
mkdir build-security_monitor

../security_monitor/init-build.sh -DPLATFORM=qemu-riscv-virt \s
    -DCMAKE_C_FLAGS="-march=rv64imac -mabi=lp64" \
    -DSIMULATION=TRUE \
    -DOPENSBI_PATH="/host/tools/opensbi"
```

Then go to the security_monitor directory and put the files of this repo inside. 

todo, create a script to do this automatically


## Run

To run the SoC simulation, go to the build-security_monitor directory and run the following command:

```bash
ninja
./simulate
```

To add some IP's to the simulation, first ensure that the IP's is correctly setup in QEMU (see the QEMU section) and then specify the IP in the simulate script arguments:

```bash
./simulate --extra-qemu-args="-bios none -device my_ip"
```




