aux_source_directory(. FFKX_BENCH_SRCS)

find_package(absl REQUIRED)
find_package(PkgConfig REQUIRED)
# due to libbpf
pkg_search_module(ZLIB REQUIRED zlib)
pkg_search_module(LIBELF REQUIRED libelf)
# jemalloc
pkg_check_modules(JEMALLOC jemalloc)
pkg_search_module(JEMALLOC REQUIRED jemalloc)
include_directories(${JEMALLOC_INCLUDE_DIRS})

find_package(benchmark REQUIRED)

add_executable(ffkx-bench ${FFKX_BENCH_SRCS})
add_dependencies(ffkx-bench libbpf)
add_dependencies(ffkx-bench bpf)

target_link_libraries(ffkx-bench benchmark::benchmark
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
	${CMAKE_BINARY_DIR}/libbpf/libbpf.a
	z
	elf
)

if (FFKX_OPT_BUILD_STATIC)
	target_link_libraries(ffkx-bench "-static")
endif (FFKX_OPT_BUILD_STATIC)

target_include_directories(ffkx-bench PRIVATE ${CMAKE_BINARY_DIR}/libbpf/usr/include)
target_include_directories(ffkx-bench PRIVATE ../include)
target_include_directories(ffkx-bench PRIVATE ../bpf/include)
target_include_directories(ffkx-bench PRIVATE ../bpf)
target_include_directories(ffkx-bench PRIVATE ../src)
target_include_directories(ffkx-bench PRIVATE .)
