#ifndef DP_H
#define DP_H

#include "core/models.h"

/* ============================================================================
 * DYNAMIC PROGRAMMING MODULE — Cyber Threat Detection Engine
 *
 * Provides classical DP algorithms mapped to cybersecurity operations:
 *   1. 0/1 Knapsack          — Budget-constrained security tool deployment
 *   2. Matrix Chain Order    — Optimal log correlation join order
 *   3. LCS                   — Attack signature similarity detection
 *   4. Optimal BST           — Frequency-optimized IP lookup
 *   5. Bellman-Ford          — Shortest attack path with trust reductions
 *   6. Floyd-Warshall        — All-pairs threat proximity
 *   7. TSP (Held-Karp)       — Optimal security audit route
 * ============================================================================ */

/* ---------------------------------------------------------------------------
 * 1. 0/1 Knapsack — Budget-Constrained Security Tool Deployment
 *
 * Selects a subset of security tools that maximizes total protection value
 * without exceeding the available budget.
 *
 * @param items     Array of KnapsackItem (name, cost, value)
 * @param n         Number of items
 * @param budget    Maximum budget capacity
 * @param selected  Output array: selected[i] = 1 if item i is chosen, 0 otherwise
 * @return          Maximum total protection value achievable
 *
 * Time complexity: O(n * budget)
 * Space complexity: O(n * budget)
 * --------------------------------------------------------------------------- */
int knapsack01(KnapsackItem items[], int n, int budget, int selected[]);

/* ---------------------------------------------------------------------------
 * 2. Matrix Chain Multiplication — Optimal Log Correlation Join Order
 *
 * Determines the optimal parenthesization for multiplying a chain of matrices
 * (representing multi-source log table joins) to minimize scalar multiplications.
 *
 * @param dims      Dimension array: matrix i has dimensions dims[i] x dims[i+1]
 * @param n         Number of matrices (dims has n+1 entries)
 * @param splits    Output 2D array: splits[i][j] stores optimal split point k
 * @return          Minimum number of scalar multiplications
 *
 * Time complexity: O(n^3)
 * Space complexity: O(n^2)
 * --------------------------------------------------------------------------- */
int matrixChainOrder(int dims[], int n, int splits[][20]);

/* ---------------------------------------------------------------------------
 * printOptimalParens — Prints the optimal parenthesization for matrix chain
 *
 * @param splits    The split table computed by matrixChainOrder
 * @param i         Start index (1-based)
 * @param j         End index (1-based)
 * --------------------------------------------------------------------------- */
void printOptimalParens(int splits[][20], int i, int j);

/* ---------------------------------------------------------------------------
 * 3. Longest Common Subsequence (LCS) — Attack Signature Similarity
 *
 * Finds the longest common subsequence between two payload strings to
 * detect attack signature variants sharing a common pattern.
 *
 * @param seq1      First payload/signature string
 * @param seq2      Second payload/signature string
 * @param result    Output buffer for the LCS string (must be large enough)
 * @return          Length of the LCS
 *
 * Time complexity: O(m * n) where m, n are string lengths
 * Space complexity: O(m * n)
 * --------------------------------------------------------------------------- */
int lcs(const char* seq1, const char* seq2, char* result);

/* ---------------------------------------------------------------------------
 * 4. Optimal Binary Search Tree — Frequency-Optimized IP Lookup
 *
 * Computes the minimum expected search cost for a BST where keys are
 * queried with known frequencies (e.g., IP address lookup probabilities).
 *
 * @param freq      Array of search frequencies/probabilities (should sum to 1.0)
 * @param n         Number of keys
 * @return          Minimum expected search cost
 *
 * Time complexity: O(n^3)
 * Space complexity: O(n^2)
 * --------------------------------------------------------------------------- */
float optimalBST(float freq[], int n);

/* ---------------------------------------------------------------------------
 * 5. Bellman-Ford — Shortest Attack Path with Trust Reductions
 *
 * Computes single-source shortest paths in a graph that may have negative
 * edge weights (representing trust penalties or risk reductions).
 *
 * @param g         Pointer to a Graph structure (uses edge list)
 * @param src       Source node index
 * @param dist      Output array: dist[i] = shortest distance from src to i
 * @param prev      Output array: prev[i] = predecessor of i on shortest path
 * @return          1 on success, 0 if a negative-weight cycle is detected
 *
 * Time complexity: O(V * E)
 * Space complexity: O(V)
 * --------------------------------------------------------------------------- */
int bellmanFord(Graph* g, int src, int dist[], int prev[]);

/* ---------------------------------------------------------------------------
 * 6. Floyd-Warshall — All-Pairs Threat Proximity
 *
 * Computes shortest paths between ALL pairs of hosts in the network for
 * global risk assessment and threat propagation analysis.
 *
 * @param g         Pointer to a Graph structure (uses adjacency matrix)
 * @param dist      Output 2D array: dist[i][j] = shortest distance from i to j
 * @param next      Output 2D array: next[i][j] = next hop from i toward j
 * @return          void
 *
 * Time complexity: O(V^3)
 * Space complexity: O(V^2)
 * --------------------------------------------------------------------------- */
void floydWarshall(Graph* g, int dist[][MAX_HOSTS], int next[][MAX_HOSTS]);

/* ---------------------------------------------------------------------------
 * printPath — Reconstructs and prints the shortest path from u to v
 *
 * @param next      The next-hop table computed by floydWarshall
 * @param u         Source node
 * @param v         Destination node
 * --------------------------------------------------------------------------- */
void printPath(int next[][MAX_HOSTS], int u, int v);

/* ---------------------------------------------------------------------------
 * 7. TSP via Held-Karp — Optimal Security Audit Route
 *
 * Finds the minimum-cost Hamiltonian cycle visiting all N nodes exactly once,
 * using bitmask DP (Held-Karp algorithm). Limited to n <= 15.
 *
 * @param dist      Distance/cost matrix between sites
 * @param n         Number of sites to audit
 * @param path      Output array: visit order of nodes in the optimal tour
 * @return          Minimum total tour cost
 *
 * Time complexity: O(2^n * n^2)
 * Space complexity: O(2^n * n)
 * --------------------------------------------------------------------------- */
int tspDP(int dist[][MAX_HOSTS], int n, int path[]);

/* ---------------------------------------------------------------------------
 * run_dp_demos — Demonstrates all 7 DP algorithms with cybersecurity test data
 * --------------------------------------------------------------------------- */
void run_dp_demos(void);
void run_standard_dp_showcase(void);

#endif
