# MSVC gates <stdatomic.h> behind a separate option on some C11 toolsets.
# Keep the existing atomic_flag implementation and its sequential consistency.
function(cdns_enable_msvc_atomics target)
  if(NOT CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    return()
  endif()

  include(CMakePushCheckState)
  include(CheckCCompilerFlag)
  include(CheckCSourceCompiles)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_FLAGS "/W4 /WX")
  # These are compile/link checks, never executions (also safe when cross building).
  set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
  set(_cdns_atomic_source [=[
#include <stdatomic.h>
static atomic_flag busy = ATOMIC_FLAG_INIT;
int main(void) {
    int held = atomic_flag_test_and_set(&busy);
    atomic_flag_clear(&busy);
    return held;
}
]=])
  set(CIPHERDNS_MSVC_C11_ATOMICS_OPTION "" CACHE INTERNAL "Selected MSVC C11 atomics option" FORCE)
  set(CIPHERDNS_MSVC_C11_ATOMICS_SUPPORTED FALSE CACHE INTERNAL "Usable MSVC C11 atomic_flag" FORCE)

  # A future toolset may support atomics without the experimental switch.
  # Do not reject __STDC_NO_ATOMICS__: MSVC can define it while supporting atomic_flag.
  check_c_source_compiles("${_cdns_atomic_source}" CIPHERDNS_MSVC_C11_ATOMICS_NATIVE)
  if(NOT CIPHERDNS_MSVC_C11_ATOMICS_NATIVE)
    check_c_compiler_flag("/experimental:c11atomics" CIPHERDNS_MSVC_C11_ATOMICS_FLAG)
    if(CIPHERDNS_MSVC_C11_ATOMICS_FLAG)
      set(CMAKE_REQUIRED_FLAGS "/W4 /WX /experimental:c11atomics")
      check_c_source_compiles("${_cdns_atomic_source}" CIPHERDNS_MSVC_C11_ATOMICS_WITH_FLAG)
    endif()
    if(NOT CIPHERDNS_MSVC_C11_ATOMICS_FLAG OR NOT CIPHERDNS_MSVC_C11_ATOMICS_WITH_FLAG)
      message(FATAL_ERROR
        "MSVC ${CMAKE_C_COMPILER_VERSION} cannot compile/link C11 atomic_flag. "
        "Use a Visual Studio 2022 17.5+ C toolset with matching headers/runtime "
        "and /experimental:c11atomics support; inspect the CMake compiler-check log.")
    endif()
    set(CIPHERDNS_MSVC_C11_ATOMICS_OPTION "/experimental:c11atomics"
      CACHE INTERNAL "Selected MSVC C11 atomics option" FORCE)
    target_compile_options(${target} INTERFACE "$<$<COMPILE_LANGUAGE:C>:/experimental:c11atomics>")
  endif()
  set(CIPHERDNS_MSVC_C11_ATOMICS_SUPPORTED TRUE CACHE INTERNAL "Usable MSVC C11 atomic_flag" FORCE)
  cmake_pop_check_state()
  message(STATUS "MSVC C11 atomic_flag available; additional option: '${CIPHERDNS_MSVC_C11_ATOMICS_OPTION}'")
endfunction()
