aux_source_directory(. FFKX_SRCS)
list(REMOVE_ITEM FFKX_SRCS ./Main.cpp)

find_package(absl REQUIRED)
find_package(PkgConfig REQUIRED)
# due to libbpf
pkg_search_module(ZLIB REQUIRED zlib)
pkg_search_module(LIBELF REQUIRED libelf)
# jemalloc
pkg_check_modules(JEMALLOC jemalloc)
pkg_search_module(JEMALLOC REQUIRED jemalloc)
include_directories(${JEMALLOC_INCLUDE_DIRS})

add_library(ffkx-obj OBJECT ${FFKX_SRCS})
add_executable(ffkx Main.cpp)
add_dependencies(ffkx-obj libbpf)
add_dependencies(ffkx libbpf)
add_dependencies(ffkx bpf)

target_link_libraries(ffkx
	ffkx-obj
	jemalloc
	absl::flags
	absl::flags_usage
	absl::flags_parse
	absl::flat_hash_map
	absl::inlined_vector
	absl::span
	absl::strings
	absl::status
	absl::statusor
	absl::random_random
	absl::random_internal_distribution_test_util
	${CMAKE_BINARY_DIR}/libbpf/libbpf.a
	z
	elf
)

if (FFKX_OPT_BUILD_STATIC)
	target_link_libraries(ffkx "-static")
endif (FFKX_OPT_BUILD_STATIC)

target_include_directories(ffkx-obj PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(ffkx-obj PRIVATE ../include)
target_include_directories(ffkx-obj PRIVATE ../bpf/include)
target_include_directories(ffkx-obj PRIVATE ../bpf)
target_include_directories(ffkx-obj PRIVATE .)
target_include_directories(ffkx PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(ffkx PRIVATE ../include)
target_include_directories(ffkx PRIVATE ../bpf/include)
target_include_directories(ffkx PRIVATE ../bpf)
target_include_directories(ffkx PRIVATE .)

