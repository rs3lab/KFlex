CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS := -O2 -g --target=bpf -Wno-compare-distinct-pointer-types
INCLUDES := -Iinclude -I. -I../libbpf/src

all: bench_data_structures.skel.h ffkx_redis.skel.h ffkx_memcached.skel.h ffkx_memcache.skel.h

%.bpf.o: %.bpf.c
	@$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

bench_data_structures.skel.h: bench_data_structures.bpf.o
	@$(BPFTOOL) gen skeleton bench_data_structures.bpf.o name bench_data_structures > bench_data_structures.skel.h

ffkx_redis.skel.h: ffkx_redis.bpf.o
	@$(BPFTOOL) gen skeleton ffkx_redis.bpf.o name ffkx_redis > ffkx_redis.skel.h

ffkx_memcached.skel.h: ffkx_memcached.bpf.o
	@$(BPFTOOL) gen skeleton ffkx_memcached.bpf.o name ffkx_memcached > ffkx_memcached.skel.h

ffkx_memcache.skel.h: ffkx_memcache.bpf.o
	@$(BPFTOOL) gen skeleton ffkx_memcache.bpf.o name ffkx_memcache > ffkx_memcache.skel.h

vmlinux.h:
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	@rm -rf *.bpf.o *.skel.h
