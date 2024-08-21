#!/bin/bash

BUILD_TYPE=Release

if [[ "$1" == "-h" ]]; then
	echo "build.sh [clean|build]"
	exit 0
fi

if [[ "$1" == "clean" ]]; then
	rm -rf .build ffkx ffkx-test ffkx-bench compile_commands.json
	pushd bpf
	make clean
	popd
	exit 0
elif [[ "$1" == "build" || "$1" == "" ]]; then
	rm -rf .build ffkx ffkx-test ffkx-bench compile_commands.json
	pushd bpf
	make clean
	popd
	mkdir -p .build
	cd .build
	cmake -G Ninja				\
	 -DCMAKE_BUILD_TYPE=$BUILD_TYPE		\
	 -DFFKX_OPT_BUILD_TESTS=ON		\
	 -DFFKX_OPT_BUILD_BENCH=ON .. &&	\
	cmake --build . &&			\
	cp src/ffkx .. &&			\
	cp tests/ffkx-test .. &&		\
	cp bench/ffkx-bench .. &&		\
	cp compile_commands.json ..
	cd ..
else
	echo "Unknown option"
	exit 1
fi
