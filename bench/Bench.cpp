// SPDX-License-Identifier: MIT
#include <benchmark/benchmark.h>
#include <getopt.h>

#include <iostream>

extern volatile int kBenchmarkSize;
extern volatile int kBenchmarkIterations;

int main(int argc, char *argv[]) {
 /*
	char opt;

  while ((opt = getopt(argc, argv, "i:s:h")) != -1) {
    switch (opt) {
      case 'i':
        kBenchmarkIterations = atoi(optarg);
        break;
      case 's':
        kBenchmarkSize = atoi(optarg);
        break;
      case 'h':
      default:
        std::cout << "Unknown option!\n";
        std::exit(1);
    }
  }

  if (kBenchmarkIterations < kBenchmarkSize || (kBenchmarkIterations % kBenchmarkSize) != 0) {
    std::cout << "Number of iterations should be a multiple of benchmark data structure size";
    std::exit(1);
  }
	*/

  std::cout << "Benchmark size: " << kBenchmarkSize << '\n';
  std::cout << "Benchmark iterations: " << kBenchmarkIterations << '\n';
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
}
