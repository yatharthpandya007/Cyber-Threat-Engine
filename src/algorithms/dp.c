/* ============================================================================
 * dp.c — Dynamic Programming Module
 * Cyber Threat Detection Engine
 *
 * Implements 7 classical DP algorithms with cybersecurity domain mappings.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <time.h>

#include "algorithms/dp.h"

/* ============================================================================
 * 1. knapsack01 — 0/1 Knapsack: Budget-Constrained Security Tool Deployment
 *
 * What it does:
 *   Uses bottom-up DP to find the subset of security tools that maximizes
 *   total protection value without exceeding the budget. After building
 *   the DP table, it backtracks to identify which items were selected.
 *
 * Cybersecurity domain mapping:
 *   A SOC team has a fixed budget and must choose from a catalog of security
 *   tools (firewalls, IDS, SIEM, etc.), each with a cost and an effectiveness
 *   score.  The algorithm finds the optimal purchase set.
 *
 * Time complexity: O(n * budget)
 * ============================================================================ */
int knapsack01(KnapsackItem items[], int n, int budget, int selected[])
{
    /* Allocate DP table: dp[i][w] = max value using items 0..i-1 with capacity w */
    int** dp = (int**)malloc((size_t)(n + 1) * sizeof(int*));
    for (int i = 0; i <= n; i++) {
        dp[i] = (int*)calloc((size_t)(budget + 1), sizeof(int));
    }

    /* Fill the table bottom-up */
    for (int i = 1; i <= n; i++) {
        for (int w = 0; w <= budget; w++) {
            /* Option 1: don't take item i-1 */
            dp[i][w] = dp[i - 1][w];
            /* Option 2: take item i-1, if it fits */
            if (items[i - 1].cost <= w) {
                int val = dp[i - 1][w - items[i - 1].cost] + items[i - 1].value;
                if (val > dp[i][w]) {
                    dp[i][w] = val;
                }
            }
        }
    }

    int result = dp[n][budget];

    /* Backtrack to find which items were selected */
    for (int i = 0; i < n; i++) {
        selected[i] = 0;
    }

    int w = budget;
    for (int i = n; i > 0; i--) {
        if (dp[i][w] != dp[i - 1][w]) {
            selected[i - 1] = 1;
            w -= items[i - 1].cost;
        }
    }

    /* Free DP table */
    for (int i = 0; i <= n; i++) {
        free(dp[i]);
    }
    free(dp);

    return result;
}

/* ============================================================================
 * 2. matrixChainOrder — Optimal Log Correlation Join Order
 *
 * What it does:
 *   Determines the optimal way to parenthesize a chain of matrix multiplications
 *   to minimize the total number of scalar multiplications.  Uses the standard
 *   bottom-up DP where we build solutions for chains of increasing length.
 *
 * Cybersecurity domain mapping:
 *   When correlating logs from multiple sources (firewall, IDS, auth logs),
 *   the order of join operations affects computational cost. Each "matrix"
 *   represents a log table, and its dimensions represent rows × columns.
 *
 * Time complexity: O(n^3)
 * ============================================================================ */
int matrixChainOrder(int dims[], int n, int splits[][20])
{
    /* m[i][j] = minimum cost of multiplying matrices i..j (1-indexed) */
    int m[20][20];
    memset(m, 0, sizeof(m));
    memset(splits, 0, (size_t)n * 20 * sizeof(int));

    /* l = chain length */
    for (int l = 2; l <= n; l++) {
        for (int i = 1; i <= n - l + 1; i++) {
            int j = i + l - 1;
            m[i][j] = INT_MAX;
            for (int k = i; k < j; k++) {
                int cost = m[i][k] + m[k + 1][j] + dims[i - 1] * dims[k] * dims[j];
                if (cost < m[i][j]) {
                    m[i][j] = cost;
                    splits[i][j] = k;
                }
            }
        }
    }

    return m[1][n];
}

/* ============================================================================
 * printOptimalParens — Prints the optimal parenthesization
 *
 * What it does:
 *   Recursively prints the parenthesized form of the optimal matrix chain
 *   multiplication order using the splits table.
 *
 * Time complexity: O(n)
 * ============================================================================ */
void printOptimalParens(int splits[][20], int i, int j)
{
    if (i == j) {
        printf("Log%d", i);
    } else {
        printf("(");
        printOptimalParens(splits, i, splits[i][j]);
        printf(" x ");
        printOptimalParens(splits, splits[i][j] + 1, j);
        printf(")");
    }
}

/* ============================================================================
 * 3. lcs — Longest Common Subsequence: Attack Signature Similarity
 *
 * What it does:
 *   Uses bottom-up DP to compute the longest common subsequence of two
 *   strings, then backtracks through the DP table to reconstruct the
 *   actual LCS string.
 *
 * Cybersecurity domain mapping:
 *   Compares two attack payloads or signatures to find the longest shared
 *   pattern, which can reveal whether one is a variant or mutation of the
 *   other (e.g., obfuscated SQL injection variants sharing a core pattern).
 *
 * Time complexity: O(m * n)
 * ============================================================================ */
int lcs(const char* seq1, const char* seq2, char* result)
{
    int m = (int)strlen(seq1);
    int n = (int)strlen(seq2);

    /* Allocate DP table: dp[i][j] = LCS length of seq1[0..i-1] and seq2[0..j-1] */
    int** dp = (int**)malloc((size_t)(m + 1) * sizeof(int*));
    for (int i = 0; i <= m; i++) {
        dp[i] = (int*)calloc((size_t)(n + 1), sizeof(int));
    }

    /* Fill the table */
    for (int i = 1; i <= m; i++) {
        for (int j = 1; j <= n; j++) {
            if (seq1[i - 1] == seq2[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
            }
        }
    }

    int lcs_len = dp[m][n];

    /* Backtrack to reconstruct the LCS */
    int idx = lcs_len;
    result[idx] = '\0';

    int i = m, j = n;
    while (i > 0 && j > 0) {
        if (seq1[i - 1] == seq2[j - 1]) {
            result[--idx] = seq1[i - 1];
            i--;
            j--;
        } else if (dp[i - 1][j] > dp[i][j - 1]) {
            i--;
        } else {
            j--;
        }
    }

    /* Free DP table */
    for (int k = 0; k <= m; k++) {
        free(dp[k]);
    }
    free(dp);

    return lcs_len;
}

/* ============================================================================
 * 4. optimalBST — Frequency-Optimized IP Lookup
 *
 * What it does:
 *   Computes the minimum expected search cost for a BST where each key has
 *   a known access frequency. Uses the standard O(n^3) DP formulation where
 *   cost[i][j] represents the optimal cost of a BST containing keys i..j.
 *
 * Cybersecurity domain mapping:
 *   In a network monitoring system, certain IPs are queried far more often
 *   than others. An optimal BST places the most frequently queried IPs
 *   near the root, minimizing average lookup time.
 *
 * Time complexity: O(n^3)
 * ============================================================================ */
float optimalBST(float freq[], int n)
{
    /* cost[i][j] = min expected search cost for keys i..j (0-indexed) */
    float cost[MAX_ITEMS][MAX_ITEMS];
    float sum[MAX_ITEMS][MAX_ITEMS];

    /* Initialize single keys and base cases */
    for (int i = 0; i < n; i++) {
        cost[i][i] = freq[i];
        sum[i][i] = freq[i];
    }

    /* Build solutions for chains of increasing length */
    for (int l = 2; l <= n; l++) {
        for (int i = 0; i <= n - l; i++) {
            int j = i + l - 1;

            /* Compute sum of frequencies for keys i..j */
            sum[i][j] = sum[i][j - 1] + freq[j];

            cost[i][j] = 1e9f;

            /* Try each key r as root of subtree i..j */
            for (int r = i; r <= j; r++) {
                float c = sum[i][j];
                if (r > i) c += cost[i][r - 1];
                if (r < j) c += cost[r + 1][j];
                if (c < cost[i][j]) {
                    cost[i][j] = c;
                }
            }
        }
    }

    return cost[0][n - 1];
}

/* ============================================================================
 * 5. bellmanFord — Shortest Attack Path with Trust Reductions
 *
 * What it does:
 *   Computes single-source shortest paths by relaxing all edges |V|-1 times.
 *   Unlike Dijkstra, it correctly handles negative edge weights.  After
 *   relaxation, it performs one more pass to detect negative-weight cycles.
 *
 * Cybersecurity domain mapping:
 *   Models network paths where some edges have negative weights representing
 *   trust bonuses or risk reductions (e.g., a VPN tunnel that reduces risk).
 *   Negative cycles would indicate an exploitable infinite-benefit loop.
 *
 * Time complexity: O(V * E)
 * ============================================================================ */
int bellmanFord(Graph* g, int src, int dist[], int prev[])
{
    int V = g->num_nodes;
    int E = g->num_edges;

    /* Initialize distances to INF, source to 0 */
    for (int i = 0; i < V; i++) {
        dist[i] = INF;
        prev[i] = -1;
    }
    dist[src] = 0;

    /* Relax all edges V-1 times */
    for (int iter = 0; iter < V - 1; iter++) {
        for (int e = 0; e < E; e++) {
            int u = g->edges[e].src;
            int v = g->edges[e].dest;
            int w = g->edges[e].weight;
            if (dist[u] != INF && dist[u] + w < dist[v]) {
                dist[v] = dist[u] + w;
                prev[v] = u;
            }
        }
    }

    /* Check for negative-weight cycles (one more pass) */
    for (int e = 0; e < E; e++) {
        int u = g->edges[e].src;
        int v = g->edges[e].dest;
        int w = g->edges[e].weight;
        if (dist[u] != INF && dist[u] + w < dist[v]) {
            return 0;  /* Negative cycle detected */
        }
    }

    return 1;  /* Success — no negative cycles */
}

/* ============================================================================
 * 6. floydWarshall — All-Pairs Threat Proximity
 *
 * What it does:
 *   Computes shortest paths between ALL pairs of nodes using the classic
 *   three-nested-loop approach. For each intermediate node k, checks if
 *   routing through k improves the path from i to j.  Also builds a
 *   next-hop table for path reconstruction.
 *
 * Cybersecurity domain mapping:
 *   Allows a SOC to assess the shortest "attack distance" between any two
 *   hosts in the network, enabling global risk assessment and identification
 *   of which hosts are most vulnerable to lateral movement from any source.
 *
 * Time complexity: O(V^3)
 * ============================================================================ */
void floydWarshall(Graph* g, int dist[][MAX_HOSTS], int next[][MAX_HOSTS])
{
    int V = g->num_nodes;

    /* Initialize from adjacency matrix */
    for (int i = 0; i < V; i++) {
        for (int j = 0; j < V; j++) {
            dist[i][j] = g->adj[i][j];
            if (g->adj[i][j] != INF && i != j) {
                next[i][j] = j;
            } else {
                next[i][j] = -1;
            }
        }
        dist[i][i] = 0;
        next[i][i] = i;
    }

    /* Main Floyd-Warshall: consider each node k as intermediate */
    for (int k = 0; k < V; k++) {
        for (int i = 0; i < V; i++) {
            for (int j = 0; j < V; j++) {
                if (dist[i][k] != INF && dist[k][j] != INF) {
                    if (dist[i][k] + dist[k][j] < dist[i][j]) {
                        dist[i][j] = dist[i][k] + dist[k][j];
                        next[i][j] = next[i][k];
                    }
                }
            }
        }
    }
}

/* ============================================================================
 * printPath — Reconstructs and prints shortest path from u to v
 *
 * What it does:
 *   Uses the next-hop table from Floyd-Warshall to print the full path
 *   from node u to node v.
 *
 * Time complexity: O(V) in the worst case
 * ============================================================================ */
void printPath(int next[][MAX_HOSTS], int u, int v)
{
    if (next[u][v] == -1) {
        printf("No path");
        return;
    }
    printf("%d", u);
    while (u != v) {
        u = next[u][v];
        printf(" -> %d", u);
    }
}

/* ============================================================================
 * 7. tspDP — Optimal Security Audit Route (Held-Karp Algorithm)
 *
 * What it does:
 *   Solves the Travelling Salesman Problem exactly using bitmask dynamic
 *   programming (Held-Karp).  dp[mask][i] stores the minimum cost to visit
 *   the set of nodes encoded in 'mask', ending at node i.  The algorithm
 *   starts from node 0, visits all other nodes, and returns to node 0.
 *
 * Cybersecurity domain mapping:
 *   A security auditor must visit N data center sites exactly once for
 *   on-site compliance checks. The algorithm finds the route that minimizes
 *   total travel cost, ensuring efficient resource allocation.
 *
 * Time complexity: O(2^n * n^2)
 * Space complexity: O(2^n * n)
 *
 * Limitation: n ≤ 15 for feasibility (2^15 = 32768 states).
 * ============================================================================ */
int tspDP(int dist[][MAX_HOSTS], int n, int path[])
{
    if (n > 15) {
        printf("Error: TSP Held-Karp limited to n <= 15 (got %d)\n", n);
        return -1;
    }

    int total_masks = 1 << n;

    /* Allocate DP and parent tables */
    int** dp = (int**)malloc((size_t)total_masks * sizeof(int*));
    int** parent = (int**)malloc((size_t)total_masks * sizeof(int*));
    for (int i = 0; i < total_masks; i++) {
        dp[i] = (int*)malloc((size_t)n * sizeof(int));
        parent[i] = (int*)malloc((size_t)n * sizeof(int));
        for (int j = 0; j < n; j++) {
            dp[i][j] = INF;
            parent[i][j] = -1;
        }
    }

    /* Base case: start at node 0 */
    dp[1][0] = 0;  /* mask = 1 (only node 0 visited), ending at node 0, cost = 0 */

    /* Fill DP table */
    for (int mask = 1; mask < total_masks; mask++) {
        for (int u = 0; u < n; u++) {
            /* Skip if u is not in the current set */
            if (!(mask & (1 << u))) continue;
            if (dp[mask][u] == INF) continue;

            /* Try extending to each unvisited node v */
            for (int v = 0; v < n; v++) {
                if (mask & (1 << v)) continue;  /* v already visited */
                if (dist[u][v] == INF) continue; /* no edge */

                int new_mask = mask | (1 << v);
                int new_cost = dp[mask][u] + dist[u][v];
                if (new_cost < dp[new_mask][v]) {
                    dp[new_mask][v] = new_cost;
                    parent[new_mask][v] = u;
                }
            }
        }
    }

    /* Find the minimum cost to complete the tour (return to node 0) */
    int full_mask = total_masks - 1;
    int min_cost = INF;
    int last_node = -1;
    for (int u = 1; u < n; u++) {
        if (dp[full_mask][u] != INF && dp[full_mask][u] + dist[u][0] < min_cost) {
            min_cost = dp[full_mask][u] + dist[u][0];
            last_node = u;
        }
    }

    /* Reconstruct the path by backtracking through parent table */
    if (last_node == -1) {
        /* No valid tour found */
        for (int i = 0; i < total_masks; i++) {
            free(dp[i]);
            free(parent[i]);
        }
        free(dp);
        free(parent);
        return INF;
    }

    /* Build path in reverse */
    int temp_path[16];
    int mask = full_mask;
    int cur = last_node;
    int idx = n - 1;
    temp_path[idx] = cur;
    for (int step = n - 2; step >= 1; step--) {
        int prev = parent[mask][cur];
        mask ^= (1 << cur);
        cur = prev;
        temp_path[step] = cur;
    }
    temp_path[0] = 0;  /* Start at node 0 */

    /* Copy to output */
    for (int i = 0; i < n; i++) {
        path[i] = temp_path[i];
    }

    /* Free DP tables */
    for (int i = 0; i < total_masks; i++) {
        free(dp[i]);
        free(parent[i]);
    }
    free(dp);
    free(parent);

    return min_cost;
}

/* ============================================================================
 * run_dp_demos — Master demonstration of all 7 DP algorithms
 *
 * Creates cybersecurity-themed test data and runs each algorithm with
 * clearly labeled output sections.
 * ============================================================================ */
void run_standard_dp_showcase(void)
{
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         DYNAMIC PROGRAMMING MODULE — DEMONSTRATIONS            ║\n");
    printf("║         Cyber Threat Detection Engine                          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    /* ====================================================================
     * DEMO 1: 0/1 Knapsack — Budget-Constrained Security Tool Deployment
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 1: 0/1 Knapsack — Budget-Constrained Security Tool Deploy\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        KnapsackItem tools[] = {
            {"Firewall",         3, 6},
            {"IDS/IPS",          4, 8},
            {"SIEM Platform",    5, 9},
            {"Endpoint AV",      2, 4},
            {"VPN Gateway",      1, 2}
        };
        int n = 5;
        int budget = 8;
        int selected[5];

        printf("  Budget: %d units\n", budget);
        printf("  Available security tools:\n");
        printf("  %-20s  %6s  %6s\n", "Tool", "Cost", "Value");
        printf("  %-20s  %6s  %6s\n", "----", "----", "-----");
        for (int i = 0; i < n; i++) {
            printf("  %-20s  %6d  %6d\n", tools[i].name, tools[i].cost, tools[i].value);
        }

        int maxVal = knapsack01(tools, n, budget, selected);

        printf("\n  Optimal deployment (max protection = %d):\n", maxVal);
        int totalCost = 0;
        for (int i = 0; i < n; i++) {
            if (selected[i]) {
                printf("    [SELECTED] %s (cost=%d, value=%d)\n",
                       tools[i].name, tools[i].cost, tools[i].value);
                totalCost += tools[i].cost;
            }
        }
        printf("  Total cost used: %d / %d\n", totalCost, budget);
        printf("  Domain: Maximize security coverage within fixed CISO budget\n\n");
    }

    /* ====================================================================
     * DEMO 2: Matrix Chain Multiplication — Optimal Log Join Order
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 2: Matrix Chain — Optimal Log Correlation Join Order\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        /* 4 log tables:
         *   Log1: 10×30 (Firewall logs)
         *   Log2: 30×5  (IDS alerts)
         *   Log3: 5×60  (Auth logs)
         *   Log4: 60×10 (DNS queries)
         */
        int dims[] = {10, 30, 5, 60, 10};
        int n = 4;
        int splits[20][20];

        printf("  Log table dimensions (rows x cols):\n");
        printf("    Log1 (Firewall):  10 x 30\n");
        printf("    Log2 (IDS):       30 x 5\n");
        printf("    Log3 (Auth):       5 x 60\n");
        printf("    Log4 (DNS):       60 x 10\n");

        int minOps = matrixChainOrder(dims, n, splits);

        printf("\n  Minimum scalar multiplications: %d\n", minOps);
        printf("  Optimal join order: ");
        printOptimalParens(splits, 1, n);
        printf("\n");
        printf("  Domain: Minimize CPU cost when correlating multi-source logs\n\n");
    }

    /* ====================================================================
     * DEMO 3: LCS — Attack Signature Similarity
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 3: LCS — Attack Signature Similarity Detection\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        const char* sig1 = "SELECT*FROM users WHERE 1=1--";
        const char* sig2 = "SELECT id FROM users WHERE x=1--";
        char result[256] = {0};

        printf("  Payload A: \"%s\"\n", sig1);
        printf("  Payload B: \"%s\"\n", sig2);

        int len = lcs(sig1, sig2, result);

        printf("\n  LCS length: %d\n", len);
        printf("  LCS string: \"%s\"\n", result);
        printf("  Similarity: %.1f%% (relative to shorter payload)\n",
               100.0 * len / ((int)strlen(sig1) < (int)strlen(sig2) ?
                              (int)strlen(sig1) : (int)strlen(sig2)));
        printf("  Domain: Detect variant SQLi payloads sharing a core pattern\n\n");
    }

    /* ====================================================================
     * DEMO 4: Optimal BST — Frequency-Optimized IP Lookup
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 4: Optimal BST — Frequency-Optimized IP Lookup\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        /* 5 IPs with different query frequencies */
        const char* ips[] = {
            "10.0.0.1", "10.0.0.5", "10.0.0.12", "10.0.0.20", "10.0.0.50"
        };
        float freq[] = {0.05f, 0.40f, 0.08f, 0.04f, 0.43f};
        int n = 5;

        printf("  IP addresses and query frequencies:\n");
        printf("  %-14s  %s\n", "IP Address", "Frequency");
        printf("  %-14s  %s\n", "----------", "---------");
        for (int i = 0; i < n; i++) {
            printf("  %-14s  %.2f\n", ips[i], freq[i]);
        }

        float cost = optimalBST(freq, n);

        printf("\n  Minimum expected search cost: %.4f\n", cost);
        printf("  (A naive balanced BST would cost more for skewed frequencies)\n");
        printf("  Domain: Place hot IPs near BST root for faster lookups\n\n");
    }

    /* ====================================================================
     * DEMO 5: Bellman-Ford — Shortest Attack Path w/ Trust Reductions
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 5: Bellman-Ford — Shortest Attack Path w/ Trust Penalties\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        /*
         * 5-node network with some negative edges (trust bonuses):
         *   0: External Attacker
         *   1: DMZ Server
         *   2: Internal Router
         *   3: Database Server
         *   4: Admin Workstation
         *
         * Edge weights: positive = risk cost, negative = trust reduction (VPN/hardened)
         */
        Graph g;
        memset(&g, 0, sizeof(Graph));
        g.num_nodes = 5;
        g.num_edges = 7;

        strcpy(g.node_names[0], "Attacker");
        strcpy(g.node_names[1], "DMZ");
        strcpy(g.node_names[2], "Router");
        strcpy(g.node_names[3], "Database");
        strcpy(g.node_names[4], "AdminWS");

        /* Edge list */
        g.edges[0] = (Edge){0, 1, 6, 0};    /* Attacker -> DMZ: risk 6 */
        g.edges[1] = (Edge){0, 2, 7, 0};    /* Attacker -> Router: risk 7 */
        g.edges[2] = (Edge){1, 2, 8, 0};    /* DMZ -> Router: risk 8 */
        g.edges[3] = (Edge){1, 3, -4, 0};   /* DMZ -> Database: -4 (hardened path) */
        g.edges[4] = (Edge){2, 3, 5, 0};    /* Router -> Database: risk 5 */
        g.edges[5] = (Edge){2, 4, -3, 0};   /* Router -> AdminWS: -3 (VPN tunnel) */
        g.edges[6] = (Edge){3, 4, 9, 0};    /* Database -> AdminWS: risk 9 */

        printf("  Network topology (5 hosts, 7 connections):\n");
        for (int i = 0; i < g.num_edges; i++) {
            printf("    %s --%d--> %s", g.node_names[g.edges[i].src],
                   g.edges[i].weight, g.node_names[g.edges[i].dest]);
            if (g.edges[i].weight < 0) printf("  (trust bonus)");
            printf("\n");
        }

        int dist[MAX_HOSTS], prev[MAX_HOSTS];
        int ok = bellmanFord(&g, 0, dist, prev);

        printf("\n  Source: %s (node 0)\n", g.node_names[0]);
        if (ok) {
            printf("  Shortest attack distances (no negative cycles):\n");
            for (int i = 0; i < g.num_nodes; i++) {
                printf("    -> %s: cost = %d", g.node_names[i], dist[i]);
                /* Print path */
                if (i != 0 && dist[i] != INF) {
                    printf("  path: ");
                    int path_buf[MAX_HOSTS];
                    int len = 0;
                    int cur = i;
                    while (cur != -1) {
                        path_buf[len++] = cur;
                        cur = prev[cur];
                    }
                    for (int p = len - 1; p >= 0; p--) {
                        printf("%s", g.node_names[path_buf[p]]);
                        if (p > 0) printf(" -> ");
                    }
                }
                printf("\n");
            }
        } else {
            printf("  WARNING: Negative-weight cycle detected! Exploitable loop.\n");
        }
        printf("  Domain: Find least-cost attack paths including trust reductions\n\n");
    }

    /* ====================================================================
     * DEMO 6: Floyd-Warshall — All-Pairs Threat Proximity
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 6: Floyd-Warshall — All-Pairs Threat Proximity\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        /*
         * 4-node network (all-pairs):
         *   0: Web Server
         *   1: App Server
         *   2: DB Server
         *   3: File Server
         */
        Graph g;
        memset(&g, 0, sizeof(Graph));
        g.num_nodes = 4;

        strcpy(g.node_names[0], "WebSrv");
        strcpy(g.node_names[1], "AppSrv");
        strcpy(g.node_names[2], "DBSrv");
        strcpy(g.node_names[3], "FileSrv");

        /* Initialize adjacency matrix */
        for (int i = 0; i < g.num_nodes; i++)
            for (int j = 0; j < g.num_nodes; j++)
                g.adj[i][j] = (i == j) ? 0 : INF;

        g.adj[0][1] = 3;   /* WebSrv -> AppSrv */
        g.adj[0][3] = 7;   /* WebSrv -> FileSrv */
        g.adj[1][0] = 8;   /* AppSrv -> WebSrv */
        g.adj[1][2] = 2;   /* AppSrv -> DBSrv */
        g.adj[2][0] = 5;   /* DBSrv -> WebSrv */
        g.adj[2][3] = 1;   /* DBSrv -> FileSrv */
        g.adj[3][0] = 2;   /* FileSrv -> WebSrv */

        printf("  Network: 4 servers (Web, App, DB, File)\n");
        printf("  Adjacency matrix (INF = no direct link):\n");
        printf("          ");
        for (int j = 0; j < g.num_nodes; j++)
            printf("%-10s", g.node_names[j]);
        printf("\n");
        for (int i = 0; i < g.num_nodes; i++) {
            printf("  %-8s", g.node_names[i]);
            for (int j = 0; j < g.num_nodes; j++) {
                if (g.adj[i][j] == INF)
                    printf("%-10s", "INF");
                else
                    printf("%-10d", g.adj[i][j]);
            }
            printf("\n");
        }

        int dist[MAX_HOSTS][MAX_HOSTS];
        int next[MAX_HOSTS][MAX_HOSTS];
        floydWarshall(&g, dist, next);

        printf("\n  All-pairs shortest distances:\n");
        printf("          ");
        for (int j = 0; j < g.num_nodes; j++)
            printf("%-10s", g.node_names[j]);
        printf("\n");
        for (int i = 0; i < g.num_nodes; i++) {
            printf("  %-8s", g.node_names[i]);
            for (int j = 0; j < g.num_nodes; j++) {
                if (dist[i][j] >= INF)
                    printf("%-10s", "INF");
                else
                    printf("%-10d", dist[i][j]);
            }
            printf("\n");
        }

        printf("\n  Example paths:\n");
        printf("    AppSrv -> FileSrv: ");
        printPath(next, 1, 3);
        printf(" (cost=%d)\n", dist[1][3]);
        printf("    FileSrv -> DBSrv:  ");
        printPath(next, 3, 2);
        printf(" (cost=%d)\n", dist[3][2]);
        printf("  Domain: Assess lateral movement risk between any host pair\n\n");
    }

    /* ====================================================================
     * DEMO 7: TSP (Held-Karp) — Optimal Security Audit Route
     * ==================================================================== */
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  DEMO 7: TSP (Held-Karp) — Optimal Security Audit Route\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    {
        /*
         * 4 data center sites:
         *   0: HQ
         *   1: East DC
         *   2: West DC
         *   3: Cloud DC
         */
        const char* sites[] = {"HQ", "East_DC", "West_DC", "Cloud_DC"};
        int n = 4;
        int dist[MAX_HOSTS][MAX_HOSTS];

        /* Initialize distance matrix */
        for (int i = 0; i < MAX_HOSTS; i++)
            for (int j = 0; j < MAX_HOSTS; j++)
                dist[i][j] = INF;

        dist[0][0] = 0; dist[0][1] = 10; dist[0][2] = 15; dist[0][3] = 20;
        dist[1][0] = 10; dist[1][1] = 0; dist[1][2] = 35; dist[1][3] = 25;
        dist[2][0] = 15; dist[2][1] = 35; dist[2][2] = 0; dist[2][3] = 30;
        dist[3][0] = 20; dist[3][1] = 25; dist[3][2] = 30; dist[3][3] = 0;

        printf("  Sites to audit: HQ, East DC, West DC, Cloud DC\n");
        printf("  Travel cost matrix:\n");
        printf("          ");
        for (int j = 0; j < n; j++)
            printf("%-12s", sites[j]);
        printf("\n");
        for (int i = 0; i < n; i++) {
            printf("  %-8s", sites[i]);
            for (int j = 0; j < n; j++) {
                printf("%-12d", dist[i][j]);
            }
            printf("\n");
        }

        int path[MAX_HOSTS];
        int minCost = tspDP(dist, n, path);

        printf("\n  Minimum audit tour cost: %d\n", minCost);
        printf("  Optimal route: ");
        for (int i = 0; i < n; i++) {
            printf("%s -> ", sites[path[i]]);
        }
        printf("%s (return)\n", sites[path[0]]);
        printf("  Domain: Minimize auditor travel while visiting all sites\n\n");
    }

    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         ALL 7 DP DEMOS COMPLETED SUCCESSFULLY                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
}

static void run_interactive_knapsack(void) {
    KnapsackItem tools[] = {
        {"NextGen Firewall (NGFW)",      3, 6},
        {"CrowdStrike EDR Agent",        2, 5},
        {"Splunk SIEM Correlation",      4, 8},
        {"Honeypot Deception Host",      1, 2},
        {"Hardware Security Module",     5, 9},
        {"DDoS Mitigation Scrubber",     3, 7},
        {"WAF (Web Application Wall)",   2, 4}
    };
    int n = 7;

    printf("\n--- INTERACTIVE CYBER DEFENSE TOOL KNAPSACK (0/1 DP) ---\n");
    printf("Available Security Tools in Catalog:\n");
    printf("  Tool Name                       | Cost ($k) | Protection Value (1-10)\n");
    printf("  --------------------------------------------------------------------\n");
    for (int i = 0; i < n; i++) {
        printf("  %-31s | $%d,000    | %d / 10\n", tools[i].name, tools[i].cost, tools[i].value);
    }
    printf("  --------------------------------------------------------------------\n\n");

    char buf[64];
    printf("Enter your company's Total Defense Budget in $k [e.g. 5, 8, 12, 16]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    int budget = atoi(buf);
    if (budget <= 0) budget = 8;
    if (budget > 30) budget = 30;

    int selected[20] = {0};
    clock_t start = clock();
    int maxVal = knapsack01(tools, n, budget, selected);
    double t = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;

    printf("\n>> Optimal Defense Portfolio Selected by 0/1 Dynamic Programming (Budget: $%d,000):\n", budget);
    int totalCost = 0;
    for (int i = 0; i < n; i++) {
        if (selected[i]) {
            printf("  [APPROVED] %-30s | Cost: $%d,000 | Score: +%d\n", tools[i].name, tools[i].cost, tools[i].value);
            totalCost += tools[i].cost;
        }
    }
    printf("--------------------------------------------------------------------\n");
    printf("  Total Budget Spent:     $%d,000 / $%d,000\n", totalCost, budget);
    printf("  Max Protection Score:   %d points\n", maxVal);
    printf("  DP Table Solve Time:    %.5f ms\n\n", t);
}

static void run_interactive_lcs(void) {
    printf("\n--- INTERACTIVE MALWARE VARIANT SIMILARITY (LCS DP) ---\n");
    char s1[256], s2[256];

    printf("Enter Attack Payload 1 [e.g. 'DROP_TABLE_USERS_WHERE_1=1']: ");
    fflush(stdout);
    if (!fgets(s1, sizeof(s1), stdin)) return;
    s1[strcspn(s1, "\r\n")] = '\0';
    if (strlen(s1) == 0) strcpy(s1, "DROP_TABLE_USERS_WHERE_1=1");

    printf("Enter Attack Payload 2 [e.g. 'SELECT_AND_DROP_TABLE_USERS']: ");
    fflush(stdout);
    if (!fgets(s2, sizeof(s2), stdin)) return;
    s2[strcspn(s2, "\r\n")] = '\0';
    if (strlen(s2) == 0) strcpy(s2, "SELECT_AND_DROP_TABLE_USERS");

    char lcsStr[256] = {0};
    clock_t start = clock();
    int lcsLen = lcs(s1, s2, lcsStr);
    double t = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;

    int minLen = (strlen(s1) < strlen(s2)) ? (int)strlen(s1) : (int)strlen(s2);
    double similarity = (minLen > 0) ? ((double)lcsLen / minLen) * 100.0 : 0.0;

    printf("\n>> Longest Common Subsequence Analysis:\n");
    printf("  Payload 1:               \"%s\" (len=%zu)\n", s1, strlen(s1));
    printf("  Payload 2:               \"%s\" (len=%zu)\n", s2, strlen(s2));
    printf("  Shared LCS Pattern:      \"%s\"\n", lcsStr);
    printf("  LCS Length:              %d characters\n", lcsLen);
    printf("  Signature Similarity:    %.1f %%\n", similarity);
    printf("  Verdict:                 %s\n",
           (similarity >= 70.0) ? "CONFIRMED POLYMORPHIC VARIANT: Same malware exploit family!" :
           (similarity >= 40.0) ? "PARTIAL MATCH: Shared library or shellcode fragments." :
                                  "UNRELATED: Signatures belong to distinct attack families.");
    printf("  DP Table Latency:        %.5f ms\n\n", t);
}

void run_dp_demos(void) {
    char choice[32];
    while (1) {
        printf("=== PHASE 5: DYNAMIC PROGRAMMING CONTROL CENTER ========================\n");
        printf("  [1] Run All Standard DP Demos (Knapsack, MatrixChain, LCS, OptBST, BF, FW, TSP)\n");
        printf("  [2] Interactive Security Budget Optimization (Enter Any Budget $k)\n");
        printf("  [3] Interactive Malware Variant Similarity (Compare Any 2 Payloads)\n");
        printf("  [B] Return to Main Engine Menu\n");
        printf("------------------------------------------------------------------------\n");
        printf("Select an action: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        choice[strcspn(choice, "\r\n")] = '\0';
        if (strlen(choice) == 0) continue;

        char c = choice[0];
        if (c == '1') run_standard_dp_showcase();
        else if (c == '2') run_interactive_knapsack();
        else if (c == '3') run_interactive_lcs();
        else if (c == 'b' || c == 'B') break;
        else printf("Invalid selection '%s'.\n\n", choice);
    }
}
