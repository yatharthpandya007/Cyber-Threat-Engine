/* ============================================================================
 * BACKTRACKING AND BRANCH-AND-BOUND MODULE — Implementation
 * ============================================================================
 * Cybersecurity Log Threat Detection Engine
 *
 * Algorithms implemented:
 *   1. N-Queens (Backtracking)         — Firewall Rule Placement
 *   2. Subset Sum (Backtracking)       — Data Exfiltration Detection
 *   3. B&B FIFO (BFS)                  — Analyst-to-Incident Assignment
 *   4. B&B LIFO (DFS)                  — Analyst-to-Incident Assignment
 *   5. B&B Least-Cost (Best-First)     — Analyst-to-Incident Assignment
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

#include "algorithms/backtracking.h"

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================ */

/*
 * _nq_is_safe
 * ----------------------------------------------------------------------------
 * Checks whether placing a queen at (row, col) is safe given the partial
 * placement in solution[0..col-1].
 *
 * A position is safe if no previously placed queen shares the same row or
 * lies on either diagonal.
 *
 * Time complexity: O(col)
 */
static bool _nq_is_safe(int solution[], int row, int col)
{
    for (int i = 0; i < col; i++) {
        /* Same row or same diagonal */
        if (solution[i] == row ||
            abs(solution[i] - row) == abs(i - col)) {
            return false;
        }
    }
    return true;
}

/*
 * _nq_solve
 * ----------------------------------------------------------------------------
 * Recursive backtracking helper for N-Queens. Tries to place a queen in
 * column `col` by iterating through all rows. On finding a valid placement,
 * recurses to the next column. When all columns are filled (col == n), a
 * complete solution is recorded.
 *
 * Time complexity: O(N!) overall across all calls
 */
static void _nq_solve(int n, int col, int current[], int solutions[][20],
                       int *count, int maxSolutions)
{
    if (*count >= maxSolutions) return;

    if (col == n) {
        /* Record complete solution */
        for (int i = 0; i < n; i++) {
            solutions[*count][i] = current[i];
        }
        (*count)++;
        return;
    }

    for (int row = 0; row < n; row++) {
        if (_nq_is_safe(current, row, col)) {
            current[col] = row;
            _nq_solve(n, col + 1, current, solutions, count, maxSolutions);
            /* Backtrack: no explicit undo needed since next iteration overwrites */
        }
    }
}

/* ============================================================================
 * 1. N-QUEENS — FIREWALL RULE PLACEMENT
 * ============================================================================ */

/*
 * solveNQueens
 * ----------------------------------------------------------------------------
 * Places N non-conflicting firewall rules across N network zones using
 * backtracking.
 *
 * Cybersecurity domain mapping: Each queen represents a firewall rule placed
 * in a network zone. Non-conflict constraints model that rules must not
 * overlap in port ranges, zones, or policy scopes.
 *
 * Time complexity: O(N!) worst case
 */
int solveNQueens(int n, int solutions[][20], int maxSolutions)
{
    if (n <= 0 || n > 20 || maxSolutions <= 0) return 0;

    int current[20];
    int count = 0;
    memset(current, 0, sizeof(current));
    _nq_solve(n, 0, current, solutions, &count, maxSolutions);
    return count;
}

/*
 * printBoard
 * ----------------------------------------------------------------------------
 * Visualizes a single N-Queens solution as an ASCII board.
 * 'Q' marks a queen, '.' marks an empty cell.
 *
 * Time complexity: O(N^2)
 */
void printBoard(int solution[], int n)
{
    for (int row = 0; row < n; row++) {
        printf("    ");
        for (int col = 0; col < n; col++) {
            if (solution[col] == row)
                printf(" Q");
            else
                printf(" .");
        }
        printf("\n");
    }
}

/* ============================================================================
 * 2. SUBSET SUM — DATA EXFILTRATION DETECTION
 * ============================================================================ */

/*
 * _subset_sum_helper
 * ----------------------------------------------------------------------------
 * Recursive backtracking helper for Subset Sum. At each index, we include
 * or exclude the element. Pruning: if the remaining sum goes negative
 * (assuming sorted input and all positive), we can skip.
 *
 * Time complexity: O(2^N) worst case
 */
static void _subset_sum_helper(int set[], int n, int target, int index,
                                int current[], int currentSize,
                                int subsets[][MAX_ITEMS], int subsetSizes[],
                                int *count, int maxSubsets, int currentSum)
{
    if (*count >= maxSubsets) return;

    if (currentSum == target) {
        /* Record this subset */
        for (int i = 0; i < currentSize; i++) {
            subsets[*count][i] = current[i];
        }
        subsetSizes[*count] = currentSize;
        (*count)++;
        /* Continue searching for more subsets (don't return) */
    }

    if (index >= n || currentSum > target) return;

    for (int i = index; i < n; i++) {
        /* Prune: if adding set[i] exceeds target, skip (only valid if sorted) */
        if (currentSum + set[i] > target) continue;

        current[currentSize] = set[i];
        _subset_sum_helper(set, n, target, i + 1, current, currentSize + 1,
                           subsets, subsetSizes, count, maxSubsets,
                           currentSum + set[i]);
    }
}

/*
 * subsetSum
 * ----------------------------------------------------------------------------
 * Finds all subsets of data transfer sizes that exactly sum to a known
 * exfiltration volume.
 *
 * Cybersecurity domain mapping: Forensic analysis of network traffic —
 * determining which observed file transfers could have composed the total
 * volume exfiltrated by a threat actor.
 *
 * Time complexity: O(2^N) worst case
 */
int subsetSum(int set[], int n, int target, int subsets[][MAX_ITEMS],
              int subsetSizes[], int maxSubsets)
{
    if (n <= 0 || target <= 0 || maxSubsets <= 0) return 0;

    int current[MAX_ITEMS];
    int count = 0;
    _subset_sum_helper(set, n, target, 0, current, 0,
                       subsets, subsetSizes, &count, maxSubsets, 0);
    return count;
}

/* ============================================================================
 * BRANCH AND BOUND — SHARED HELPERS
 * ============================================================================ */

/*
 * _bb_calculate_bound
 * ----------------------------------------------------------------------------
 * Computes a lower bound on the total assignment cost from the current
 * partial state. For each unassigned analyst (level and beyond), adds the
 * minimum cost among all unassigned incidents.
 *
 * This is an admissible (never overestimates the true minimum) heuristic
 * for the assignment problem.
 *
 * Cybersecurity domain mapping: Estimates the best-case remaining response
 * time if each remaining analyst could be assigned their cheapest available
 * incident.
 *
 * Time complexity: O(N^2)
 */
static int _bb_calculate_bound(int costMatrix[][MAX_HOSTS], int n,
                                BBNode *node)
{
    int bound = node->cost;

    for (int i = node->level; i < n; i++) {
        int minCost = INT_MAX;
        for (int j = 0; j < n; j++) {
            if (!node->assigned[j]) {
                if (costMatrix[i][j] < minCost) {
                    minCost = costMatrix[i][j];
                }
            }
        }
        if (minCost == INT_MAX) minCost = 0;
        bound += minCost;
    }

    return bound;
}

/*
 * _bb_make_child
 * ----------------------------------------------------------------------------
 * Creates a child BBNode from a parent by assigning analyst at parent->level
 * to incident j.
 *
 * Time complexity: O(N) for copying arrays
 */
static BBNode _bb_make_child(int costMatrix[][MAX_HOSTS], int n,
                              BBNode *parent, int j)
{
    BBNode child;
    child.level = parent->level + 1;
    child.cost  = parent->cost + costMatrix[parent->level][j];

    memcpy(child.assignment, parent->assignment, sizeof(int) * MAX_HOSTS);
    memcpy(child.assigned, parent->assigned, sizeof(int) * MAX_HOSTS);

    child.assignment[parent->level] = j;
    child.assigned[j] = 1;

    child.bound = _bb_calculate_bound(costMatrix, n, &child);

    return child;
}

/* Maximum number of nodes in the B&B queue/stack/priority queue.
 * For a problem of size up to MAX_HOSTS, N! can be large, but with pruning
 * the actual number of live nodes is much smaller. We use a generous buffer. */
#define BB_MAX_NODES 100000

/* ============================================================================
 * 3. BRANCH AND BOUND — FIFO (BFS)
 * ============================================================================ */

/*
 * bbFIFO
 * ----------------------------------------------------------------------------
 * Solves the analyst-to-incident assignment problem using Branch and Bound
 * with a FIFO queue for breadth-first state-space exploration.
 *
 * Cybersecurity domain mapping: Assign N analysts to N incidents minimizing
 * total response time. BFS explores all partial assignments at depth d
 * before depth d+1, giving a systematic enumeration.
 *
 * Time complexity: O(N! * N) worst case, pruned by bounding
 */
int bbFIFO(int costMatrix[][MAX_HOSTS], int n, int assignment[])
{
    if (n <= 0) return 0;

    /* FIFO queue implemented as circular buffer */
    BBNode *queue = (BBNode *)malloc(sizeof(BBNode) * BB_MAX_NODES);
    if (!queue) {
        fprintf(stderr, "Error: memory allocation failed in bbFIFO\n");
        return -1;
    }

    int front = 0, rear = 0;
    int nodesExplored = 0;
    int bestCost = INT_MAX;
    int bestAssignment[MAX_HOSTS];
    memset(bestAssignment, -1, sizeof(bestAssignment));

    /* Root node: no analyst assigned yet */
    BBNode root;
    root.level = 0;
    root.cost  = 0;
    memset(root.assignment, -1, sizeof(root.assignment));
    memset(root.assigned, 0, sizeof(root.assigned));
    root.bound = _bb_calculate_bound(costMatrix, n, &root);

    queue[rear++] = root;

    while (front != rear) {
        BBNode current = queue[front++];
        if (front >= BB_MAX_NODES) front = 0;  /* wrap around */
        nodesExplored++;

        /* Pruning: skip if lower bound exceeds best known */
        if (current.bound >= bestCost) continue;

        /* If this is a complete assignment */
        if (current.level == n) {
            if (current.cost < bestCost) {
                bestCost = current.cost;
                memcpy(bestAssignment, current.assignment, sizeof(int) * n);
            }
            continue;
        }

        /* Generate children: assign current analyst to each available incident */
        for (int j = 0; j < n; j++) {
            if (!current.assigned[j]) {
                BBNode child = _bb_make_child(costMatrix, n, &current, j);

                if (child.bound < bestCost) {
                    if (child.level == n) {
                        /* Complete solution */
                        if (child.cost < bestCost) {
                            bestCost = child.cost;
                            memcpy(bestAssignment, child.assignment,
                                   sizeof(int) * n);
                        }
                        nodesExplored++;
                    } else {
                        queue[rear++] = child;
                        if (rear >= BB_MAX_NODES) rear = 0;
                    }
                }
            }
        }
    }

    memcpy(assignment, bestAssignment, sizeof(int) * n);
    printf("    [FIFO/BFS] Nodes explored: %d\n", nodesExplored);

    free(queue);
    return bestCost;
}

/* ============================================================================
 * 4. BRANCH AND BOUND — LIFO (DFS)
 * ============================================================================ */

/*
 * bbLIFO
 * ----------------------------------------------------------------------------
 * Solves the analyst-to-incident assignment problem using Branch and Bound
 * with a LIFO stack for depth-first state-space exploration.
 *
 * Cybersecurity domain mapping: Same assignment problem. DFS tends to find
 * feasible solutions quickly (reaching full depth early) which can tighten
 * the upper bound and enable more aggressive pruning.
 *
 * Time complexity: O(N! * N) worst case, pruned by bounding
 */
int bbLIFO(int costMatrix[][MAX_HOSTS], int n, int assignment[])
{
    if (n <= 0) return 0;

    /* LIFO stack implemented as array + top pointer */
    BBNode *stack = (BBNode *)malloc(sizeof(BBNode) * BB_MAX_NODES);
    if (!stack) {
        fprintf(stderr, "Error: memory allocation failed in bbLIFO\n");
        return -1;
    }

    int top = -1;
    int nodesExplored = 0;
    int bestCost = INT_MAX;
    int bestAssignment[MAX_HOSTS];
    memset(bestAssignment, -1, sizeof(bestAssignment));

    /* Root node */
    BBNode root;
    root.level = 0;
    root.cost  = 0;
    memset(root.assignment, -1, sizeof(root.assignment));
    memset(root.assigned, 0, sizeof(root.assigned));
    root.bound = _bb_calculate_bound(costMatrix, n, &root);

    stack[++top] = root;

    while (top >= 0) {
        BBNode current = stack[top--];
        nodesExplored++;

        /* Pruning */
        if (current.bound >= bestCost) continue;

        /* Complete assignment */
        if (current.level == n) {
            if (current.cost < bestCost) {
                bestCost = current.cost;
                memcpy(bestAssignment, current.assignment, sizeof(int) * n);
            }
            continue;
        }

        /* Generate children and push onto stack */
        for (int j = n - 1; j >= 0; j--) {
            if (!current.assigned[j]) {
                BBNode child = _bb_make_child(costMatrix, n, &current, j);

                if (child.bound < bestCost) {
                    if (child.level == n) {
                        if (child.cost < bestCost) {
                            bestCost = child.cost;
                            memcpy(bestAssignment, child.assignment,
                                   sizeof(int) * n);
                        }
                        nodesExplored++;
                    } else {
                        if (top + 1 < BB_MAX_NODES) {
                            stack[++top] = child;
                        }
                    }
                }
            }
        }
    }

    memcpy(assignment, bestAssignment, sizeof(int) * n);
    printf("    [LIFO/DFS] Nodes explored: %d\n", nodesExplored);

    free(stack);
    return bestCost;
}

/* ============================================================================
 * 5. BRANCH AND BOUND — LEAST-COST (BEST-FIRST)
 * ============================================================================ */

/*
 * bbLeastCost
 * ----------------------------------------------------------------------------
 * Solves the analyst-to-incident assignment problem using Branch and Bound
 * with a priority queue ordered by (bound) — always expanding the most
 * promising node first.
 *
 * Cybersecurity domain mapping: Same assignment problem. Best-first search
 * typically finds the optimal solution with the fewest node expansions,
 * making it the most efficient B&B strategy in practice.
 *
 * The priority queue is implemented via linear-scan extraction of the node
 * with the smallest bound from a dynamic array.
 *
 * Time complexity: O(N! * N) worst case, pruned by bounding;
 *                  each extraction is O(k) for k live nodes.
 */
int bbLeastCost(int costMatrix[][MAX_HOSTS], int n, int assignment[])
{
    if (n <= 0) return 0;

    /* Priority queue: array of nodes, extract-min via linear scan */
    BBNode *pq = (BBNode *)malloc(sizeof(BBNode) * BB_MAX_NODES);
    if (!pq) {
        fprintf(stderr, "Error: memory allocation failed in bbLeastCost\n");
        return -1;
    }

    int pqSize = 0;
    int nodesExplored = 0;
    int bestCost = INT_MAX;
    int bestAssignment[MAX_HOSTS];
    memset(bestAssignment, -1, sizeof(bestAssignment));

    /* Root node */
    BBNode root;
    root.level = 0;
    root.cost  = 0;
    memset(root.assignment, -1, sizeof(root.assignment));
    memset(root.assigned, 0, sizeof(root.assigned));
    root.bound = _bb_calculate_bound(costMatrix, n, &root);

    pq[pqSize++] = root;

    while (pqSize > 0) {
        /* Find node with smallest bound (best-first) */
        int minIdx = 0;
        for (int i = 1; i < pqSize; i++) {
            if (pq[i].bound < pq[minIdx].bound) {
                minIdx = i;
            }
        }

        BBNode current = pq[minIdx];
        /* Remove by swapping with last element */
        pq[minIdx] = pq[pqSize - 1];
        pqSize--;

        nodesExplored++;

        /* Pruning */
        if (current.bound >= bestCost) continue;

        /* Complete assignment */
        if (current.level == n) {
            if (current.cost < bestCost) {
                bestCost = current.cost;
                memcpy(bestAssignment, current.assignment, sizeof(int) * n);
            }
            continue;
        }

        /* Generate children */
        for (int j = 0; j < n; j++) {
            if (!current.assigned[j]) {
                BBNode child = _bb_make_child(costMatrix, n, &current, j);

                if (child.bound < bestCost) {
                    if (child.level == n) {
                        if (child.cost < bestCost) {
                            bestCost = child.cost;
                            memcpy(bestAssignment, child.assignment,
                                   sizeof(int) * n);
                        }
                        nodesExplored++;
                    } else {
                        if (pqSize < BB_MAX_NODES) {
                            pq[pqSize++] = child;
                        }
                    }
                }
            }
        }
    }

    memcpy(assignment, bestAssignment, sizeof(int) * n);
    printf("    [Least-Cost/Best-First] Nodes explored: %d\n", nodesExplored);

    free(pq);
    return bestCost;
}

/* ============================================================================
 * DEMO — run_backtracking_demos
 * ============================================================================ */

/*
 * run_backtracking_demos
 * ----------------------------------------------------------------------------
 * Demonstrates all five algorithms in this module with cybersecurity-themed
 * test data and clearly labeled terminal output.
 */
void run_backtracking_demos(void)
{
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║   BACKTRACKING & BRANCH-AND-BOUND MODULE — DEMONSTRATIONS     ║\n");
    printf("║   Cybersecurity Log Threat Detection Engine                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    /* ========================================================================
     * DEMO 1: N-Queens — Firewall Rule Placement
     * ======================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 1: N-Queens Backtracking — Firewall Rule Placement\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Scenario: Place 5 non-conflicting firewall rules across 5\n");
    printf("  network zones (DMZ, Internal, Guest, IoT, Server).\n");
    printf("  Constraints: No two rules may share the same port range,\n");
    printf("  zone, or overlapping policy scope (row/col/diagonal).\n\n");

    {
        int n = 5;
        int solutions[20][20]; /* up to 20 solutions, board up to 20x20 */
        int maxSolutions = 20;

        int totalFound = solveNQueens(n, solutions, maxSolutions);

        printf("  Total valid placements found: %d\n\n", totalFound);

        const char *zones[] = {"DMZ", "Internal", "Guest", "IoT", "Server"};
        int showCount = totalFound < 2 ? totalFound : 2;

        for (int s = 0; s < showCount; s++) {
            printf("  ── Configuration #%d ──\n", s + 1);
            printBoard(solutions[s], n);
            printf("    Mapping:\n");
            for (int c = 0; c < n; c++) {
                printf("      Zone %-10s → Rule in port-range slot %d\n",
                       zones[c], solutions[s][c]);
            }
            printf("\n");
        }

        if (totalFound > 2) {
            printf("  ... (%d more configurations omitted)\n\n", totalFound - 2);
        }
    }

    /* ========================================================================
     * DEMO 2: Subset Sum — Data Exfiltration Detection
     * ======================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 2: Subset Sum Backtracking — Data Exfiltration Detection\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Scenario: A SIEM alert flagged 512 MB total exfiltration.\n");
    printf("  Observed outbound transfers (MB): 64, 128, 32, 256, 96, 48, 160\n");
    printf("  Find which transfers compose the exfiltrated volume.\n\n");

    {
        int transfers[] = {64, 128, 32, 256, 96, 48, 160};
        int n = 7;
        int target = 512;

        int subsets[20][MAX_ITEMS];
        int subsetSizes[20];
        int maxSubsets = 20;

        int found = subsetSum(transfers, n, target, subsets, subsetSizes,
                              maxSubsets);

        printf("  Target exfiltration volume: %d MB\n", target);
        printf("  Matching transfer combinations found: %d\n\n", found);

        for (int i = 0; i < found; i++) {
            printf("    Combination #%d: ", i + 1);
            int sum = 0;
            for (int j = 0; j < subsetSizes[i]; j++) {
                if (j > 0) printf(" + ");
                printf("%d", subsets[i][j]);
                sum += subsets[i][j];
            }
            printf(" = %d MB\n", sum);
        }

        if (found > 0) {
            printf("\n  [!] FORENSIC FINDING: %d possible exfiltration "
                   "reconstructions identified.\n", found);
            printf("      Recommend reviewing source IPs for these transfer "
                   "sizes.\n");
        } else {
            printf("\n  [✓] No exact match found — exfiltration volume may "
                   "include partial transfers.\n");
        }
        printf("\n");
    }

    /* ========================================================================
     * DEMO 3-5: Branch and Bound — Analyst-to-Incident Assignment
     * ======================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 3–5: Branch & Bound — Analyst-to-Incident Assignment\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  Scenario: 4 SOC analysts must be assigned to 4 active\n");
    printf("  incidents. Each analyst has different response times (minutes)\n");
    printf("  for each incident type. Minimize total response time.\n\n");

    {
        /*
         * Cost matrix: response time in minutes
         *                    Incident 0   Incident 1   Incident 2   Incident 3
         *                    (Ransomware) (Phishing)   (DDoS)       (Insider)
         * Analyst 0 (Alice)       9           2           7            8
         * Analyst 1 (Bob)         6           4           3            7
         * Analyst 2 (Carol)       5           8           1            8
         * Analyst 3 (Dave)        7           6           9            4
         */
        int costMatrix[MAX_HOSTS][MAX_HOSTS] = {
            { 9,  2,  7,  8},
            { 6,  4,  3,  7},
            { 5,  8,  1,  8},
            { 7,  6,  9,  4}
        };
        int n = 4;

        const char *analysts[]  = {"Alice", "Bob", "Carol", "Dave"};
        const char *incidents[] = {"Ransomware", "Phishing", "DDoS", "Insider Threat"};

        printf("  Cost Matrix (response time in minutes):\n");
        printf("  %-12s", "");
        for (int j = 0; j < n; j++) {
            printf("  %-14s", incidents[j]);
        }
        printf("\n");
        for (int i = 0; i < n; i++) {
            printf("  %-12s", analysts[i]);
            for (int j = 0; j < n; j++) {
                printf("  %-14d", costMatrix[i][j]);
            }
            printf("\n");
        }
        printf("\n");

        /* --- FIFO (BFS) --- */
        int assignFIFO[MAX_HOSTS];
        printf("  ┌─ Strategy 1: FIFO / Breadth-First Search ─────────────┐\n");
        int costFIFO = bbFIFO(costMatrix, n, assignFIFO);
        printf("    Optimal total response time: %d minutes\n", costFIFO);
        printf("    Assignment:\n");
        for (int i = 0; i < n; i++) {
            printf("      %-8s → %-14s (cost: %d min)\n",
                   analysts[i], incidents[assignFIFO[i]],
                   costMatrix[i][assignFIFO[i]]);
        }
        printf("  └────────────────────────────────────────────────────────┘\n\n");

        /* --- LIFO (DFS) --- */
        int assignLIFO[MAX_HOSTS];
        printf("  ┌─ Strategy 2: LIFO / Depth-First Search ───────────────┐\n");
        int costLIFO = bbLIFO(costMatrix, n, assignLIFO);
        printf("    Optimal total response time: %d minutes\n", costLIFO);
        printf("    Assignment:\n");
        for (int i = 0; i < n; i++) {
            printf("      %-8s → %-14s (cost: %d min)\n",
                   analysts[i], incidents[assignLIFO[i]],
                   costMatrix[i][assignLIFO[i]]);
        }
        printf("  └────────────────────────────────────────────────────────┘\n\n");

        /* --- Least-Cost (Best-First) --- */
        int assignLC[MAX_HOSTS];
        printf("  ┌─ Strategy 3: Least-Cost / Best-First Search ──────────┐\n");
        int costLC = bbLeastCost(costMatrix, n, assignLC);
        printf("    Optimal total response time: %d minutes\n", costLC);
        printf("    Assignment:\n");
        for (int i = 0; i < n; i++) {
            printf("      %-8s → %-14s (cost: %d min)\n",
                   analysts[i], incidents[assignLC[i]],
                   costMatrix[i][assignLC[i]]);
        }
        printf("  └────────────────────────────────────────────────────────┘\n\n");

        /* --- Comparison --- */
        printf("  ╔═══════════════════════════════════════════════════════════╗\n");
        printf("  ║  COMPARISON SUMMARY                                      ║\n");
        printf("  ╠═══════════════════════════════════════════════════════════╣\n");
        printf("  ║  All three strategies find optimal cost: %d minutes      ║\n",
               costFIFO);
        printf("  ║                                                          ║\n");
        printf("  ║  Key insight: All strategies find the same optimum but   ║\n");
        printf("  ║  differ in exploration efficiency. Least-Cost (Best-     ║\n");
        printf("  ║  First) typically explores the fewest nodes by always    ║\n");
        printf("  ║  expanding the most promising partial assignment.        ║\n");
        printf("  ╚═══════════════════════════════════════════════════════════╝\n\n");
    }

    printf("═══════════════════════════════════════════════════════════════════\n");
    printf("  All Backtracking & Branch-and-Bound demos complete.\n");
    printf("═══════════════════════════════════════════════════════════════════\n\n");
}
