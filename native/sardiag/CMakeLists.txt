# sardiag - optional network diagnostics for the secure-access-relay agent.
#
# CMake is here for consumers who expect it; scripts/task.ps1 and the Makefile
# drive a direct compiler invocation instead, because four source files do not
# need a build system and the direct call is one line somebody can read.

cmake_minimum_required(VERSION 3.15)
project(sardiag C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SARDIAG_SOURCES
    src/sardiag.c
    src/jbuf.c
    src/collect_windows.c
    src/collect_stub.c
)

add_library(sardiag SHARED ${SARDIAG_SOURCES})
target_include_directories(sardiag PUBLIC include PRIVATE src)

# Exports are declared with __declspec(dllexport) behind this define. Without it
# the library builds, links, loads, and exports nothing - a failure that looks
# like a missing file at runtime.
target_compile_definitions(sardiag PRIVATE SARDIAG_BUILD_DLL)

if(MSVC)
    target_compile_options(sardiag PRIVATE /W4 /WX)
else()
    # -Wconversion matters more than usual here: this code converts between
    # Windows integer types and fixed-width ones constantly, and a silent
    # narrowing is how a length becomes wrong.
    target_compile_options(sardiag PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Werror)
endif()

if(WIN32)
    target_link_libraries(sardiag PRIVATE ws2_32 iphlpapi winhttp)
endif()

enable_testing()
add_executable(sardiag_tests tests/test_sardiag.c ${SARDIAG_SOURCES})
target_include_directories(sardiag_tests PRIVATE include src)
if(WIN32)
    target_link_libraries(sardiag_tests PRIVATE ws2_32 iphlpapi winhttp)
endif()
add_test(NAME sardiag_tests COMMAND sardiag_tests)
