#ifndef BACKTRACKING_H
#define BACKTRACKING_H

#include "core/models.h"

/* ============================================================================
 * BACKTRACKING AND BRANCH-AND-BOUND MODULE
 * ============================================================================
 * Domain: Cybersecurity Threat Detection Engine
 *
 * This module implements backtracking and branch-and-bound algorithms
 * applied to cybersecurity optimization problems:
 *
 *   1. N-Queens (Backtracking) — Firewall Rule Placement
 *   2. Subset Sum (Backtracking) — Data Exfiltration Detection
 *   3. Branch & Bound FIFO — Optimal Analyst-to-Incident Assignment (BFS)
 *   4. Branch & Bound LIFO — Optimal Analyst-to-Incident Assignment (DFS)
 *   5. Branch & Bound Least-Cost — Optimal Analyst-to-Incident Assignment (Best-First)
 * ============================================================================ */

/* --------------------------------------------------------------------------
 * Internal node type used by all three Branch-and-Bound variants.
 * Represents a partial state in the assignment search tree.
 * -------------------------------------------------------------------------- */
typedef struct {
    int level;                    /* Current analyst being assigned         */
    int assignment[MAX_HOSTS];    /* Partial assignment so far              */
    int assigned[MAX_HOSTS];      /* Which incidents are already taken      */
    int cost;                     /* Cost of partial assignment             */
    int bound;                    /* Lower bound on total cost              */
} BBNode;

/* ============================================================================
 * 1. N-QUEENS — FIREWALL RULE PLACEMENT
 * ============================================================================ */

/*
 * solveNQueens
 * ----------------------------------------------------------------------------
 * Places N non-conflicting firewall rules across N network zones using the
 * classic N-Queens backtracking algorithm.
 *
 * Cybersecurity mapping: Each "queen" is a firewall rule; no two rules may
 * share the same row (port range), column (zone), or diagonal (overlapping
 * policy scope).
 *
 * Parameters:
 *   n             — board size / number of zones (max 20)
 *   solutions     — output array: solutions[s][col] = row of queen in col
 *                   for solution s
 *   maxSolutions  — stop after finding this many solutions
 *
 * Returns: number of solutions found (up to maxSolutions)
 * Time complexity: O(N!) in the worst case
 */
int solveNQueens(int n, int solutions[][20], int maxSolutions);

/*
 * printBoard
 * ----------------------------------------------------------------------------
 * Visualizes a single N-Queens solution as an ASCII board.
 *
 * Parameters:
 *   solution — array where solution[col] = row of queen in column col
 *   n        — board size
 */
void printBoard(int solution[], int n);

/* ============================================================================
 * 2. SUBSET SUM — DATA EXFILTRATION DETECTION
 * ============================================================================ */

/*
 * subsetSum
 * ----------------------------------------------------------------------------
 * Finds all subsets of data transfer sizes that sum to a known exfiltration
 * volume, using backtracking.
 *
 * Cybersecurity mapping: Given observed transfer sizes (in MB), determine
 * which combinations exactly match a suspected exfiltration total — useful
 * for forensic reconstruction of data theft events.
 *
 * Parameters:
 *   set         — array of transfer sizes (positive integers)
 *   n           — number of elements in set
 *   target      — target exfiltration volume (MB)
 *   subsets     — output: subsets[i][] holds elements of the i-th solution
 *   subsetSizes — output: subsetSizes[i] = number of elements in subset i
 *   maxSubsets  — stop after finding this many subsets
 *
 * Returns: number of subsets found (up to maxSubsets)
 * Time complexity: O(2^N) in the worst case
 */
int subsetSum(int set[], int n, int target, int subsets[][MAX_ITEMS],
              int subsetSizes[], int maxSubsets);

/* ============================================================================
 * 3. BRANCH AND BOUND — FIFO (BFS)
 * ============================================================================ */

/*
 * bbFIFO
 * ----------------------------------------------------------------------------
 * Solves the analyst-to-incident assignment problem using Branch and Bound
 * with a FIFO queue (breadth-first exploration).
 *
 * Cybersecurity mapping: Assign N security analysts to N active incidents
 * such that total response time (cost) is minimized. BFS explores all nodes
 * at a given depth before going deeper.
 *
 * Parameters:
 *   costMatrix — costMatrix[i][j] = time for analyst i to handle incident j
 *   n          — number of analysts / incidents
 *   assignment — output: assignment[i] = incident assigned to analyst i
 *
 * Returns: minimum total cost
 * Time complexity: O(N! * N) worst case, pruned by bounding
 */
int bbFIFO(int costMatrix[][MAX_HOSTS], int n, int assignment[]);

/* ============================================================================
 * 4. BRANCH AND BOUND — LIFO (DFS)
 * ============================================================================ */

/*
 * bbLIFO
 * ----------------------------------------------------------------------------
 * Solves the same assignment problem using Branch and Bound with a LIFO
 * stack (depth-first exploration).
 *
 * Cybersecurity mapping: Same as FIFO but explores depth-first, often
 * finding feasible solutions faster at the cost of potentially exploring
 * more nodes before proving optimality.
 *
 * Parameters:  Same as bbFIFO
 * Returns:     minimum total cost
 * Time complexity: O(N! * N) worst case, pruned by bounding
 */
int bbLIFO(int costMatrix[][MAX_HOSTS], int n, int assignment[]);

/* ============================================================================
 * 5. BRANCH AND BOUND — LEAST-COST (BEST-FIRST)
 * ============================================================================ */

/*
 * bbLeastCost
 * ----------------------------------------------------------------------------
 * Solves the same assignment problem using Branch and Bound with a priority
 * queue ordered by least estimated cost (best-first exploration).
 *
 * Cybersecurity mapping: Same as above but always expands the most promising
 * partial assignment first, typically reaching the optimum with fewest node
 * expansions.
 *
 * Parameters:  Same as bbFIFO
 * Returns:     minimum total cost
 * Time complexity: O(N! * N) worst case, pruned by bounding
 */
int bbLeastCost(int costMatrix[][MAX_HOSTS], int n, int assignment[]);

/* ============================================================================
 * DEMO
 * ============================================================================ */

/*
 * run_backtracking_demos
 * ----------------------------------------------------------------------------
 * Demonstrates all 5 algorithms with cybersecurity-themed test data.
 */
void run_backtracking_demos(void);
void run_standard_backtracking_showcase(void);

#endif /* BACKTRACKING_H */
