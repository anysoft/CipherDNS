# SDK root may be a relocated Buildroot ARMv5 soft-float glibc/musl/uClibc SDK.
# Run the SDK's relocate-sdk.sh on its supported build host when required.
if("$ENV{CIPHERDNS_TOOLCHAIN_ROOT}" STREQUAL "")
  message(FATAL_ERROR "Set CIPHERDNS_TOOLCHAIN_ROOT to the Buildroot SDK root")
endif()
include("${CMAKE_CURRENT_LIST_DIR}/linux-armv5.cmake")
