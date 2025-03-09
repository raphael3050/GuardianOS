set(CMAKE_HOST_SYSTEM "Linux-6.10.14-linuxkit")
set(CMAKE_HOST_SYSTEM_NAME "Linux")
set(CMAKE_HOST_SYSTEM_VERSION "6.10.14-linuxkit")
set(CMAKE_HOST_SYSTEM_PROCESSOR "aarch64")

include("/host/build-security_monitor/gcc.cmake")

set(CMAKE_SYSTEM "Generic")
set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_SYSTEM_VERSION "")
set(CMAKE_SYSTEM_PROCESSOR "seL4CPU")

set(CMAKE_CROSSCOMPILING "TRUE")

set(CMAKE_SYSTEM_LOADED 1)
