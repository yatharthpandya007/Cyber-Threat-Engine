#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>

typedef struct {
    const char* algorithm_name;
    const char* category;
    const char* asymptotic_time;
    const char* asymptotic_space;
    double empirical_time_ms;
    const char* complexity_class;
} BenchmarkEntry;

void run_all_benchmarks(void);
void print_complexity_table(void);
void print_reduction_mapping(void);
void print_production_strategy(void);
void print_recurrence_solutions(void);

#endif
