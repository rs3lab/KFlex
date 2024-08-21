cmake_minimum_required(VERSION 3.5)
project(ffkx VERSION 0.1 DESCRIPTION "ffkx")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BUILD_SHARED_LIBS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -Wextra			\
	-Wno-gnu-zero-variadic-macro-arguments -Wno-nested-anon-types		\
	-Wno-gnu-anonymous-struct -Wno-variadic-macros				\
	-Wno-zero-length-array -Wno-c99-designator				\
	-Wno-missing-field-initializers"
)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O1 -fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(FFKX_OPT_BUILD_STATIC "Build static executable" OFF)
option(FFKX_OPT_BUILD_TESTS "Build test suite" OFF)
option(FFKX_OPT_BUILD_BENCH "Build benchmark suite" OFF)

message("-- Build options:")
message("--   FFKX_OPT_BUILD_STATIC=${FFKX_OPT_BUILD_STATIC}")
message("--   FFKX_OPT_BUILD_TESTS=${FFKX_OPT_BUILD_TESTS}")
message("--   FFKX_OPT_BUILD_BENCH=${FFKX_OPT_BUILD_BENCH}")

if (FFKX_OPT_BUILD_STATIC)
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(BUILD_SHARED_LIBS OFF)
endif (FFKX_OPT_BUILD_STATIC)

# libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/libbpf/src
    INSTALL_DIR ${CMAKE_BINARY_DIR}/libbpf
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/libbpf/libbpf.a
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E env BUILD_STATIC_ONLY=1
		  OBJDIR=<INSTALL_DIR> DESTDIR=<INSTALL_DIR>
		  make -j -C <SOURCE_DIR> install
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

# bpf
include(ExternalProject)
ExternalProject_Add(bpf
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/bpf
    INSTALL_DIR ""
    BUILD_BYPRODUCTS ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make -j
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
)

add_subdirectory(src)
if (FFKX_OPT_BUILD_TESTS)
	add_subdirectory(tests)
endif (FFKX_OPT_BUILD_TESTS)
if (FFKX_OPT_BUILD_BENCH)
	add_subdirectory(bench)
endif (FFKX_OPT_BUILD_BENCH)
