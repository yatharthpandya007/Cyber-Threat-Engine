/**
 * =============================================================================
 * flow.h — Network Flow Algorithms for Cybersecurity Threat Engine
 * =============================================================================
 *
 * Module: NETWORK FLOW
 * Domain: Maximum bandwidth allocation, optimal analyst-incident assignment
 *
 * Algorithms:
 *   1. Ford-Fulkerson (Edmonds-Karp BFS variant)  — Max network bandwidth
 *   2. Maximum Bipartite Matching (via max-flow)   — Analyst-incident pairing
 *
 * =============================================================================
 */

#ifndef FLOW_H
#define FLOW_H

#include "core/models.h"

/* ============================================================================
 * FORD-FULKERSON (Edmonds-Karp BFS Variant)
 * ============================================================================
 *
 * Computes the maximum flow from source to sink in a directed network
 * with integer capacities using BFS-based augmenting paths.
 *
 * Cybersecurity Domain:
 *   Maximum Network Bandwidth Allocation — determines the maximum data
 *   throughput from an entry point (e.g., Internet Gateway) to a critical
 *   server (e.g., Database) under per-link bandwidth constraints.
 *
 * Parameters:
 *   capacity  — capacity[i][j] = bandwidth capacity of directed link i→j
 *   n         — number of nodes in the network (must be <= MAX_HOSTS)
 *   source    — index of the source node
 *   sink      — index of the sink node
 *   flow      — output: flow[i][j] = actual flow routed on edge i→j
 *
 * Returns:
 *   The maximum flow value (total bandwidth from source to sink).
 *
 * Time Complexity: O(V * E²) — Edmonds-Karp guarantee
 */
int fordFulkerson(int capacity[][MAX_HOSTS], int n,
                  int source, int sink,
                  int flow[][MAX_HOSTS]);

/* ============================================================================
 * PRINT FLOW NETWORK
 * ============================================================================
 *
 * Prints a human-readable summary of each edge showing its capacity versus
 * the actual flow assigned by the Ford-Fulkerson algorithm.
 *
 * Parameters:
 *   capacity — the original capacity matrix
 *   flow     — the flow matrix computed by fordFulkerson()
 *   n        — number of nodes
 *   names    — human-readable node labels (e.g., "Firewall", "DMZ_Server")
 */
void printFlowNetwork(int capacity[][MAX_HOSTS], int flow[][MAX_HOSTS],
                      int n, char names[][32]);

/* ============================================================================
 * MAXIMUM BIPARTITE MATCHING (via reduction to Max-Flow)
 * ============================================================================
 *
 * Finds the maximum number of 1-to-1 pairings between two disjoint sets
 * (analysts and incidents) given a compatibility relation, by constructing
 * a flow network and running Ford-Fulkerson.
 *
 * Cybersecurity Domain:
 *   Analyst-to-Incident Optimal Assignment — given a compatibility matrix
 *   describing which SOC analysts are qualified to handle which security
 *   incidents, finds the maximum set of non-overlapping assignments.
 *
 * Parameters:
 *   compatibility — compatibility[i][j] = 1 if analyst i can handle incident j
 *   numAnalysts   — number of analysts (left partition)
 *   numIncidents  — number of incidents (right partition)
 *   matching      — output: matching[i] = j means analyst i is paired with
 *                   incident j; matching[i] = -1 if analyst i is unmatched
 *
 * Returns:
 *   Size of the maximum matching (number of successful pairings).
 *
 * Time Complexity: O(V * E²) where V = numAnalysts + numIncidents + 2
 */
int maxBipartiteMatching(int compatibility[][MAX_HOSTS],
                         int numAnalysts, int numIncidents,
                         int matching[]);

/* ============================================================================
 * PRINT MATCHING
 * ============================================================================
 *
 * Prints the analyst-to-incident assignment result in a human-readable format.
 *
 * Parameters:
 *   matching      — matching[i] = incident index for analyst i, or -1
 *   numAnalysts   — number of analysts
 *   analystNames  — display names for analysts
 *   incidentNames — display names for incidents
 */
void printMatching(int matching[], int numAnalysts,
                   char analystNames[][32], char incidentNames[][64]);

/* ============================================================================
 * DEMO DRIVER
 * ============================================================================
 *
 * Runs all network flow demonstrations with cybersecurity-themed test data.
 */
void run_flow_demos(void);
void run_standard_flow_showcase(void);

#endif /* FLOW_H */
