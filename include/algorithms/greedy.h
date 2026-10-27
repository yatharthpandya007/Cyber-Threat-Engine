#ifndef GREEDY_H
#define GREEDY_H

#include "core/models.h"

/* ============================================================================
 * GREEDY ALGORITHMS MODULE — Cybersecurity Log Threat Detection Engine
 *
 * Provides greedy algorithm implementations mapped to cybersecurity domains:
 *   1. Activity Selection     — Incident Response Scheduling
 *   2. Interval Partitioning  — SOC Analyst Shift Allocation
 *   3. Huffman Coding         — Log Compression
 *   4. Dijkstra's Algorithm   — Fastest Attack Path
 *   5. Prim's MST             — Minimum-Cost Secure Backbone
 *   6. Kruskal's MST          — Alternative Backbone (Union-Find)
 * ============================================================================ */

/* --------------------------------------------------------------------------
 * 1. Activity Selection (Greedy by finish time)
 *
 * Domain: Incident Response Scheduling — select maximum non-overlapping
 *         response tasks from a set of time-bounded activities.
 *
 * Parameters:
 *   activities[] — array of Activity structs (id, start, finish, description)
 *   n            — number of activities
 *   selected[]   — output array filled with indices of chosen activities
 *
 * Returns: count of selected activities
 * Time Complexity: O(n log n) due to sorting
 * -------------------------------------------------------------------------- */
int activitySelection(Activity activities[], int n, int selected[]);

/* --------------------------------------------------------------------------
 * 2. Interval Partitioning (Greedy)
 *
 * Domain: SOC Analyst Shift Allocation — determine the minimum number of
 *         analysts needed to cover all overlapping alert monitoring windows.
 *
 * Parameters:
 *   activities[] — array of Activity structs representing alert windows
 *   n            — number of activities
 *
 * Returns: minimum number of partitions (analysts) needed
 * Time Complexity: O(n log n) due to sorting
 * -------------------------------------------------------------------------- */
int intervalPartitioning(Activity activities[], int n);

/* --------------------------------------------------------------------------
 * 3. Huffman Coding (Greedy tree construction)
 *
 * Domain: Log Compression — compress high-frequency log tokens for efficient
 *         archival and storage optimisation.
 *
 * buildHuffmanTree:
 *   chars[]  — array of characters (log tokens)
 *   freqs[]  — corresponding frequency of each character
 *   n        — number of distinct characters
 *   Returns: pointer to root of constructed Huffman tree
 *   Time Complexity: O(n^2) with array-based min-heap extraction
 *
 * printHuffmanCodes:
 *   root — pointer to root of Huffman tree
 *   arr  — working buffer for code bits during traversal
 *   top  — current depth (start with 0)
 *   Time Complexity: O(n) traversal
 *
 * freeHuffmanTree:
 *   root — pointer to root; recursively frees all nodes
 *   Time Complexity: O(n)
 * -------------------------------------------------------------------------- */
HuffmanNode* buildHuffmanTree(char chars[], int freqs[], int n);
void printHuffmanCodes(HuffmanNode* root, int arr[], int top);
void freeHuffmanTree(HuffmanNode* root);

/* --------------------------------------------------------------------------
 * 4. Dijkstra's Algorithm (Greedy shortest path)
 *
 * Domain: Fastest Attack Path — find the shortest weighted path from a
 *         compromised host to every other host in the network.
 *
 * Parameters:
 *   g      — pointer to Graph (uses adjacency matrix; 0 = no edge)
 *   src    — source node index
 *   dist[] — output array of shortest distances from src
 *   prev[] — output array of predecessor nodes (-1 if none)
 *
 * Time Complexity: O(V^2) with array-based min extraction
 * -------------------------------------------------------------------------- */
void dijkstra(Graph* g, int src, int dist[], int prev[]);

/* --------------------------------------------------------------------------
 * 5. Prim's MST (Greedy minimum spanning tree)
 *
 * Domain: Minimum-Cost Secure Backbone — find the cheapest way to connect
 *         all network segments with encrypted links.
 *
 * Parameters:
 *   g          — pointer to Graph (uses adjacency matrix)
 *   mstEdges[] — output array filled with edges of the MST
 *   mstSize    — pointer set to number of MST edges
 *
 * Returns: total MST weight (sum of all edge weights)
 * Time Complexity: O(V^2)
 * -------------------------------------------------------------------------- */
int primMST(Graph* g, Edge mstEdges[], int* mstSize);

/* --------------------------------------------------------------------------
 * 6. Kruskal's MST (Greedy with Union-Find)
 *
 * Domain: Alternative Backbone Design — compare results with Prim's to
 *         validate minimum spanning tree correctness.
 *
 * Parameters:
 *   g          — pointer to Graph (uses edge list: g->edges, g->num_edges)
 *   mstEdges[] — output array filled with edges of the MST
 *   mstSize    — pointer set to number of MST edges
 *
 * Returns: total MST weight
 * Time Complexity: O(E log E) due to sorting, amortised near-O(E α(V))
 *                  with path compression and union by rank
 * -------------------------------------------------------------------------- */
int kruskalMST(Graph* g, Edge mstEdges[], int* mstSize);

/* --------------------------------------------------------------------------
 * Demo / Driver
 *
 * Demonstrates all 6 greedy algorithms with cybersecurity-themed test data
 * and clearly labelled terminal output sections.
 * -------------------------------------------------------------------------- */
void run_greedy_demos(void);
void run_standard_greedy_showcase(void);

#endif /* GREEDY_H */
