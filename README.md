# Fast, Flexible, and Practical Kernel Extensions

The ability to safely extend OS kernel functionality is a long-standing goal in OS design, with the widespread use of the eBPF framework in Linux and Windows demonstrating the benefits of such extensibility. However, existing solutions for kernel extensibility (including eBPF) are limited and constrain users either in the extent of functionality that they can offload to the kernel or the performance overheads incurred by their extensions.

We present KFlex: a new approach to kernel extensibility that strikes an improved balance between the expressivity and performance of kernel extensions. To do so, KFlex separates the safety of kernel-owned resources (e.g., kernel memory) from the safety of extension-specific resources (e.g., extension memory). This separation enables KFlex to use distinct, bespoke mechanisms to enforce each safety property—automated verification and lightweight runtime checks, respectively—which enables the offload of diverse functionality while incurring low runtime overheads.

We realize KFlex in the context of Linux. We demonstrate that KFlex enables users to offload functionality that cannot be offloaded today and provides significant end-to-end performance benefits for applications. Several of KFlex’s proposed mechanisms have been upstreamed into the Linux kernel mainline, with efforts ongoing for full integration.

The paper is publicly available at [this link](https://rs3lab.github.io/assets/papers/2024/dwivedi:kflex.pdf).

## Build Instructions

### Dependencies

For Ubuntu, install the following dependencies:

```bash
$ sudo apt install build-essential libgtest-dev libgcc-13-dev \
    libstdc++-13-dev libelf-dev zlib1g-dev gcc clang cmake ninja-build \
    bear libbenchmark-dev pkg-config
```

### Latest LLVM

To build KFlex, latest LLVM (> 18.0) is needed. Build instructions to build from
source are provided below.

You need ninja, cmake and gcc-c++ as build requisites for LLVM. Once you
have that set up, proceed with building the latest LLVM and clang version
from the git repositories::

```bash
$ git clone https://github.com/llvm/llvm-project.git
$ mkdir -p llvm-project/llvm/build
$ cd llvm-project/llvm/build
$ cmake .. -G "Ninja" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
        -DLLVM_ENABLE_PROJECTS="clang"    \
        -DCMAKE_BUILD_TYPE=Release        \
        -DLLVM_BUILD_RUNTIME=OFF
$ ninja
```

### Building KFlex

```bash
$ git submodule update --init
$ BPFTOOL=../bpftool CLANG=/path/to/llvm/clone/llvm-project/llvm/build/bin/clang ./build.sh
```

### Building the kernel

Running applications using KFlex requires a custom kernel, that is included as a
submodule. Use your distribution's `.config` to build the kernel by copying it
into kernel source, and `make olddefconfig` to apply it to `v6.9`. Then, run the
following commands to install it:

```bash
$ make -j$(nproc)
$ sudo make modules_install
$ sudo make install
```

## Running Applications

The default port used is 6969. The ifindex is the index of the network interface
to which programs will be attached.

### Memcached offload for GETS/SETS

```bash
$ ./ffkx --kmemcached --ifindex <NR>
```

A message will be printed once the offload is initialized. Then, use
`memtier-benchmark`, `memcaslap`, or any other memcache protocol aware client to
send requests. An example client invocation where `config` is a memcaslap
config with SETS:GETS ratio is:

```bash
memcaslap -s <hostname>:6969 -F config -U -T 128 -c 128 -S 1s -t 30s
```

### Redis offload for GETS/SETS

```bash
$ ./ffkx --kmemcache --ifindex <NR>
```

A message will be printed once the offload is initialized. Then, use
`memtier-benchmark`, `redis-benchmark`, or any Redis protocol aware client to
send requests. An example client invocation with SETS:GETS ratio is:

```bash
memtier_benchmark -s <hostname> -p 6969 --protocol=redis -d 64 -n 10000 -t 64 --ratio 10:90
```

### Redis offload for ZADD

```bash
$ ./ffkx --kredis --ifindex <NR>
```

A message will be printed once the offload is initialized. Then, use
`redis-benchmark`, or any Redis protocol aware client to
send ZADD requests. An example client invocation is:

```bash
redis-benchmark --threads 64 -h <hostname> -p 6969 -r 1000000 -n 2000000 zadd f__rand_int__f __rand_int__ ele:rand__rand_int__:__rand_int__
```

### Data Structures

Simply run the integrated test suite built with the source, which will automate
everything and print results to stdout.

```bash
$ ./ffkx-bench
```

All results will be printed using Google Benchmark, and `--benchmark_output` can
be used to output to different formats for post processing.

### Guard Emissions

After running the data structure benchmarks, the kernel's `dmesg` log will be
populated with the statistics. The program names will be cut off in the message,
but the order and example output is given below.

```bash
$ sudo dmesg | grep ffkx_
...
[709104.842956] prog=bench_ffkx_link range_analysis_call=4 elided=4 # Linked List Update
[709104.843231] prog=bench_ffkx_link range_analysis_call=1 elided=1 # Linked List Lookup
[709104.843443] prog=bench_ffkx_link range_analysis_call=2 elided=2 # Linked List Delete
[709104.848522] prog=bench_ffkx_rbtr range_analysis_call=15 elided=15 # RBTree Update
[709104.849048] prog=bench_ffkx_rbtr range_analysis_call=2 elided=2 # RBTree Lookup
[709104.851461] prog=bench_ffkx_rbtr range_analysis_call=29 elided=25 # RBTree Delete
[709104.852080] prog=bench_ffkx_hash range_analysis_call=2 elided=0 # Hashmap Init
[709104.901533] prog=bench_ffkx_hash range_analysis_call=10 elided=8 # Hashmap Update
[709104.902205] prog=bench_ffkx_hash range_analysis_call=4 elided=3 # Hashmap Lookup
[709104.902805] prog=bench_ffkx_hash range_analysis_call=3 elided=2 # Hashmap Delete
[709104.904134] prog=bench_ffkx_skip range_analysis_call=15 elided=10 # Skiplist Update
[709104.904470] prog=bench_ffkx_skip range_analysis_call=3 elided=2 # Skiplist Lookup
[709104.904660] prog=bench_ffkx_skip range_analysis_call=9 elided=4 # Skiplist Delete
[709104.905863] prog=bench_ffkx_coun range_analysis_call=0 elided=0 # Countminsketch
[709104.905926] prog=bench_ffkx_coun range_analysis_call=0 elided=0 # Countsketch
...
```

For more details, see the [webpage](https://rs3lab.github.io/KFlex).
