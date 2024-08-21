FROM ubuntu:rolling
LABEL Description="Build environment"
ENV HOME "/root"

RUN apt update && apt install -y --no-install-recommends \
    build-essential libgtest-dev libgcc-13-dev libstdc++-13-dev \
    libelf-dev zlib1g-dev gcc clang cmake ninja-build bear \
    libabsl-dev libbenchmark-dev pkg-config libjemalloc2 libjemalloc-dev
