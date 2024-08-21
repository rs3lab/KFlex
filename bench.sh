#!/bin/bash
# TODO Set performance governor

taskset -c 0 ./ffkx-bench --benchmark_filter=Zipfian --benchmark_format=csv
