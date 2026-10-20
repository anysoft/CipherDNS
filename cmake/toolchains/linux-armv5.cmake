set(CMAKE_SYSTEM_PROCESSOR armv5)
set(CDNS_DEFAULT_PREFIX arm-linux-gnueabi-)
set(CMAKE_C_FLAGS_INIT "-march=armv5te -mfloat-abi=soft")
include("${CMAKE_CURRENT_LIST_DIR}/_linux-common.cmake")
