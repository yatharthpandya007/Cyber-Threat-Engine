#include <stdio.h>
#include <string.h>
#include "engine/cli.h"
#include "engine/benchmark.h"
#include "core/constraints.h"
#include "algorithms/sorting.h"
#include "algorithms/searching.h"
#include "algorithms/divide_conquer.h"
#include "algorithms/greedy.h"
#include "algorithms/dp.h"
#include "algorithms/backtracking.h"
#include "algorithms/flow.h"
#include "algorithms/strings.h"

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--interactive") == 0 || strcmp(argv[1], "-i") == 0) {
            run_interactive_cli();
            return 0;
        } else if (strcmp(argv[1], "--benchmark") == 0 || strcmp(argv[1], "-b") == 0) {
            print_banner();
            run_all_benchmarks();
            return 0;
        } else if (strcmp(argv[1], "--report") == 0 || strcmp(argv[1], "-r") == 0) {
            print_banner();
            print_recurrence_solutions();
            print_complexity_table();
            print_reduction_mapping();
            print_production_strategy();
            return 0;
        } else if (strcmp(argv[1], "--module") == 0 || strcmp(argv[1], "-m") == 0) {
            if (argc < 3) {
                printf("Error: Missing module name. Options: constraints, sorting, searching, dc, greedy, dp, backtracking, flow, strings\n");
                return 1;
            }
            print_banner();
            const char* mod = argv[2];
            if (strcmp(mod, "constraints") == 0) run_constraints_demos();
            else if (strcmp(mod, "sorting") == 0) run_sorting_demos();
            else if (strcmp(mod, "searching") == 0) run_searching_demos();
            else if (strcmp(mod, "dc") == 0 || strcmp(mod, "divide_conquer") == 0) run_divide_conquer_demos();
            else if (strcmp(mod, "greedy") == 0) run_greedy_demos();
            else if (strcmp(mod, "dp") == 0) run_dp_demos();
            else if (strcmp(mod, "backtracking") == 0) run_backtracking_demos();
            else if (strcmp(mod, "flow") == 0) run_flow_demos();
            else if (strcmp(mod, "strings") == 0) run_strings_demos();
            else {
                printf("Unknown module '%s'.\n", mod);
                return 1;
            }
            return 0;
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: %s [OPTION]\n", argv[0]);
            printf("Options:\n");
            printf("  --all            Run all modules end-to-end (default if no flag given)\n");
            printf("  --interactive    Launch the interactive terminal menu\n");
            printf("  --module <name>  Run a single module (e.g., sorting, dp, flow, etc.)\n");
            printf("  --benchmark      Run empirical benchmark stress tests\n");
            printf("  --report         Display theoretical recurrence proofs and complexity matrix\n");
            printf("  --help           Show this help text\n");
            return 0;
        }
    }

    // Default execution: run all engine modules end-to-end for a complete showcase
    run_all_engine_modules();
    return 0;
}
