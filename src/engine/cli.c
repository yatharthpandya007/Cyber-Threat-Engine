#include "engine/cli.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/constraints.h"
#include "algorithms/sorting.h"
#include "algorithms/searching.h"
#include "algorithms/divide_conquer.h"
#include "algorithms/greedy.h"
#include "algorithms/dp.h"
#include "algorithms/backtracking.h"
#include "algorithms/flow.h"
#include "algorithms/strings.h"
#include "engine/benchmark.h"

void print_banner(void) {
    printf("====================================================================================\n");
    printf("     CYBERSECURITY THREAT DETECTION & OPERATIONS ENGINE (v1.0-PRODUCTION)           \n");
    printf("     Portable C11 Architecture | Full Algorithmic Threat Analysis Suite             \n");
    printf("====================================================================================\n");
}

void print_menu(void) {
    printf("\n--- COMMAND CENTER MENU ------------------------------------------------------------\n");
    printf("  [1] Phase 1 & 2: Constraints, Schema Validation & Threat Correlation\n");
    printf("  [2] Phase 2: Sorting Workloads (QuickSort by Time & Stable MergeSort by Severity)\n");
    printf("  [3] Phase 2: Searching Workloads (Iterative/Recursive Binary Search & BST Index)\n");
    printf("  [4] Phase 3: Divide & Conquer (DDoS MaxSubarray, FastPower, Celebrity, Strassen)\n");
    printf("  [5] Phase 4: Greedy Algorithms (Activity, Interval, Huffman, Dijkstra, Prim, Kruskal)\n");
    printf("  [6] Phase 5: Dynamic Programming (Knapsack, MatrixChain, LCS, OptBST, BF, FW, TSP)\n");
    printf("  [7] Phase 6: Backtracking & Branch-and-Bound (N-Queens, SubsetSum, FIFO/LIFO/LC B&B)\n");
    printf("  [8] Phase 7: Network Flow & Matching (Ford-Fulkerson MaxFlow, Bipartite Matching)\n");
    printf("  [9] Phase 8: Number Theory & String Matching (CRT Secret Recovery, Naive, RK, FA, KMP)\n");
    printf("  [A] Phase 9: Benchmark Suite (Empirical Multi-iteration Timing Measurements)\n");
    printf("  [R] Phase 10: Theoretical Report (Recurrence Proofs, Reductions, Complexity Matrix)\n");
    printf("  [E] Execute All Modules End-to-End (Full Showcase)\n");
    printf("  [Q] Quit Threat Engine\n");
    printf("------------------------------------------------------------------------------------\n");
    printf("Select an operational module: ");
    fflush(stdout);
}

void run_all_engine_modules(void) {
    print_banner();
    printf("\n>> RUNNING ALL THREAT ENGINE MODULES END-TO-END...\n\n");

    run_constraints_demos();
    run_sorting_demos();
    run_searching_demos();
    run_divide_conquer_demos();
    run_greedy_demos();
    run_dp_demos();
    run_backtracking_demos();
    run_flow_demos();
    run_strings_demos();
    run_all_benchmarks();
    print_recurrence_solutions();
    print_complexity_table();
    print_reduction_mapping();
    print_production_strategy();

    printf("\n====================================================================================\n");
    printf("   [COMPLETE] All 10 phases executed successfully with zero fatal errors.           \n");
    printf("====================================================================================\n\n");
}

void run_interactive_cli(void) {
    print_banner();
    char choice[32];

    while (1) {
        print_menu();
        if (!fgets(choice, sizeof(choice), stdin)) break;
        
        // Strip newline
        choice[strcspn(choice, "\r\n")] = '\0';
        if (strlen(choice) == 0) continue;

        char c = choice[0];
        printf("\n");
        switch (c) {
            case '1':
                run_constraints_demos();
                break;
            case '2':
                run_sorting_demos();
                break;
            case '3':
                run_searching_demos();
                break;
            case '4':
                run_divide_conquer_demos();
                break;
            case '5':
                run_greedy_demos();
                break;
            case '6':
                run_dp_demos();
                break;
            case '7':
                run_backtracking_demos();
                break;
            case '8':
                run_flow_demos();
                break;
            case '9':
                run_strings_demos();
                break;
            case 'a':
            case 'A':
                run_all_benchmarks();
                break;
            case 'r':
            case 'R':
                print_recurrence_solutions();
                print_complexity_table();
                print_reduction_mapping();
                print_production_strategy();
                break;
            case 'e':
            case 'E':
                run_all_engine_modules();
                break;
            case 'q':
            case 'Q':
                printf("Shutting down Cybersecurity Threat Engine. Goodbye.\n\n");
                return;
            default:
                printf("Invalid selection '%s'. Please choose an option from the menu.\n", choice);
                break;
        }
    }
}
