set(CMAKE_SYSTEM_PROCESSOR armv7)
set(CDNS_DEFAULT_PREFIX arm-linux-gnueabihf-)
set(CMAKE_C_FLAGS_INIT "-march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard")
include("${CMAKE_CURRENT_LIST_DIR}/_linux-common.cmake")
