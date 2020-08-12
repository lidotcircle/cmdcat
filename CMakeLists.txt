cmake_minimum_required(VERSION 3.4)

project(cmdcat)
set(CMDCAT_VERSION "1.0.0")
set(CMAKE_PROJECT_VERSION ${CMDCAT_VERSION})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(__CXX_VERSION 17)

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

check_function_exists(fork HAVE_FORK)
check_function_exists(vfork HAVE_VFORK)
check_function_exists(rfork HAVE_RFORK)
check_function_exists(clone HAVE_CLONE)
check_function_exists(clone3 HAVE_CLONE3)

check_symbol_exists(_NSGetEnviron crt_externs.h HAVE_NSGETENVIRON)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/lib/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(APPLE)
    add_compile_definitions(APPLE)
endif()

set(CMAKE_CXX_FLAGS "-std=gnu++17 -g ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS   "-g ${CMAKE_C_FLAGS}")

set(CPACK_PACKAGE_NAME "cmdcat")
set(CPACK_PACKAGE_CONTACT "prack")
set(CPACK_PACKAGE_VENDOR ${CPACK_PACKAGE_CONTACT})
set(CPACK_PACKAGE_VERSION ${CMDCAT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README  "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_URL "http://github.com/analyman/cmdcat")
set(CPACK_RPM_PACKAGE_DESCRIPTION "cmdcat is a tool to record commands which execute by a command")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)


set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(./third_party/json)
add_subdirectory(./lib)


set(EXEC_NAME cmdcat)
set(EXEC_MAIN ./bin/main.cc)
set(EXEC_LIB mmmm)
set(EXEC_CXX_SRC
    ./bin/server.cc
)

add_library(${EXEC_LIB} STATIC ${EXEC_CXX_SRC})
add_dependencies(${EXEC_LIB} nlohmann_json)
target_link_libraries(${EXEC_LIB} PRIVATE nlohmann_json)
target_link_libraries(${EXEC_LIB} PRIVATE Threads::Threads)

add_executable(${EXEC_NAME} ${EXEC_MAIN})
add_dependencies(${EXEC_NAME} nlohmann_json)
add_dependencies(${EXEC_NAME} ${EXEC_LIB})

target_link_libraries(${EXEC_NAME} PRIVATE nlohmann_json)
target_link_libraries(${EXEC_NAME} PRIVATE ${EXEC_LIB})

# test #{
include_directories("${CMAKE_CURRENT_LIST_DIR}/bin")
file(GLOB TEST_FILES_CPP "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cpp")
file(GLOB TEST_FILES_CC  "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cc")
file(GLOB TEST_FILES_CX  "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cx")
file(GLOB TEST_FILES     "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.c")
list(APPEND TEST_FILES ${TEST_FILES_CPP} ${TEST_FILES_CC} ${TEST_FILES_CX})
foreach (test_file IN LISTS TEST_FILES)
    get_filename_component(fname ${test_file} NAME_WE)
    string(LENGTH ${fname} fname_len)
    math(EXPR name_len "${fname_len} - 5")
    string(SUBSTRING ${fname} 5 ${name_len} execname)
    message(STATUS "test=${execname}")
    add_executable(${execname} ${test_file})
    set_property(TARGET ${execname} PROPERTY CXX_STANDARD ${__CXX_VERSION})
    add_dependencies(${execname} ${EXEC_LIB})
    add_dependencies(${execname} nlohmann_json)
    add_dependencies(${execname} ccat)
    target_link_libraries(${execname} ${EXEC_LIB})
    target_link_libraries(${execname} nlohmann_json)
    target_link_libraries(${execname} Threads::Threads)
    target_link_libraries(${execname} ccat)
    set_target_properties(${execname} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endforeach()

add_executable(execfork ./tests/exec-test.cc)
set_property(TARGET execfork PROPERTY CXX_STANDARD ${__CXX_VERSION})
set_target_properties(execfork PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
#}

