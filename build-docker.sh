#!/bin/bash
rm -rf .build ekcache ekcache-test
docker build -t ekcache -f Dockerfile .
docker run -it --rm --name=ekcache -w $PWD -e BUILD_TYPE=${1:-Debug}	\
--mount type=bind,source=$PWD,target=$PWD ekcache bash -c		\
'mkdir .build; cd .build; cmake -G Ninja		\
	-DCMAKE_BUILD_TYPE=$BUILD_TYPE			\
	-DEKCACHE_OPT_BUILD_STATIC=ON			\
	-DEKCACHE_OPT_BUILD_TESTS=ON		\
	-DEKCACHE_OPT_BUILD_BENCH=ON .. &&		\
	bear -- cmake --build . &&			\
	cp src/ekcache ..; cp tests/ekcache-test ..;	\
	cp bench/ekcache-bench ..; cp compile_commands.json ..'
