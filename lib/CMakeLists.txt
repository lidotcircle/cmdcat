cmake_minimum_required(VERSION 2.8)
project(libcmdcat C)
set(LIBCMDCAT_VERSION "1.0.0")

set(CMAKE_C_FLAGS "-g -std=c99 -D_GNU_SOURCE ${CMAKE_C_FLAGS}")

include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckIncludeFile)
check_function_exists(execve HAVE_EXECVE)
check_function_exists(execv HAVE_EXECV)
check_function_exists(execvpe HAVE_EXECVPE)
check_function_exists(execvp HAVE_EXECVP)
check_function_exists(execvP HAVE_EXECVP2)
check_function_exists(exect HAVE_EXECT)
check_function_exists(execl HAVE_EXECL)
check_function_exists(execlp HAVE_EXECLP)
check_function_exists(execle HAVE_EXECLE)
check_function_exists(posix_spawn HAVE_POSIX_SPAWN)
check_function_exists(posix_spawnp HAVE_POSIX_SPAWNP)

check_function_exists(fork  HAVE_FORK)
check_function_exists(vfork HAVE_VFORK)
check_function_exists(rfork HAVE_RFORK)
check_function_exists(clone HAVE_CLONE)
check_function_exists(clone3 HAVE_CLONE3)

check_symbol_exists(_NSGetEnviron crt_externs.h HAVE_NSGETENVIRON)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})


set(LIBNAME ccat)
set(C_SRC
    ./connect.c
    ./exec.c
    ./fork.c
    ./utils.c
)

add_library(${LIBNAME} SHARED ${C_SRC})
target_link_libraries(${LIBNAME} ${CMAKE_DL_LIBS})

if(THREADS_HAVE_PTHREAD_ARG)
    set_property(TARGET ${LIBNAME} PROPERTY COMPILE_OPTIONS "-pthread")
    set_property(TARGET ${LIBNAME} PROPERTY INTERFACE_COMPILE_OPTIONS "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(${LIBNAME} "${CMAKE_THREAD_LIBS_INIT}")
endif()

if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
    set_target_properties(${LIBNAME} PROPERTIES INSTALL_RPATH "@loader_path/${EAR_LIB_PATH}")
endif()

install(TARGETS ${LIBNAME} DESTINATION ${CMAKE_INSTALL_LIBDIR})
