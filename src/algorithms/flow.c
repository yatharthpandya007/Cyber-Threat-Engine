/**
 * =============================================================================
 * flow.c — Network Flow Algorithms for Cybersecurity Threat Engine
 * =============================================================================
 *
 * Module: NETWORK FLOW
 *
 * Implements:
 *   1. Ford-Fulkerson (Edmonds-Karp BFS variant) — Maximum bandwidth allocation
 *   2. Maximum Bipartite Matching via max-flow   — Analyst-incident assignment
 *
 * All algorithms use standard C11 libraries only.
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include "algorithms/flow.h"

/* ============================================================================
 * INTERNAL: BFS to find an augmenting path in the residual graph
 * ============================================================================
 *
 * Performs a breadth-first search from source to sink in the residual graph.
 * If a path exists, fills `parent[]` with the predecessor of each node on
 * the path.
 *
 * Cybersecurity mapping:
 *   Discovers a viable data route through the network from entry point
 *   to critical asset that still has unused bandwidth.
 *
 * Time Complexity: O(V + E) per BFS invocation
 *
 * Parameters:
 *   residual — residual capacity matrix
 *   n        — number of nodes
 *   source   — source node index
 *   sink     — sink node index
 *   parent   — output: parent[v] = predecessor of v on the BFS path
 *
 * Returns:
 *   true if an augmenting path was found, false otherwise.
 */
static bool bfs(int residual[][MAX_HOSTS], int n,
                int source, int sink, int parent[])
{
    bool visited[MAX_HOSTS];
    memset(visited, false, sizeof(visited));

    /* Simple queue using a fixed-size array */
    int queue[MAX_HOSTS];
    int front = 0, rear = 0;

    visited[source] = true;
    parent[source] = -1;
    queue[rear++] = source;

    while (front < rear) {
        int u = queue[front++];

        for (int v = 0; v < n; v++) {
            /* Visit unvisited node v if there is residual capacity u→v */
            if (!visited[v] && residual[u][v] > 0) {
                visited[v] = true;
                parent[v] = u;

                if (v == sink) {
                    return true;  /* Path found — early exit */
                }

                queue[rear++] = v;
            }
        }
    }

    return false;  /* No augmenting path exists */
}

/* ============================================================================
 * FORD-FULKERSON (Edmonds-Karp BFS Variant)
 * ============================================================================
 *
 * Computes the maximum flow from source to sink using BFS-based augmenting
 * paths (Edmonds-Karp algorithm). This guarantees polynomial time complexity
 * of O(V * E²), unlike the basic DFS-based Ford-Fulkerson which may not
 * terminate for irrational capacities.
 *
 * Cybersecurity Domain Mapping:
 *   Maximum Network Bandwidth Allocation — determines the maximum aggregate
 *   data throughput that can be routed from an Internet Gateway to a
 *   critical Database server, respecting per-link bandwidth constraints.
 *   This is essential for capacity planning, DDoS impact analysis, and
 *   understanding bottleneck links in a network topology.
 *
 * Algorithm (CLRS Chapter 26):
 *   1. Initialize residual graph = copy of capacity graph.
 *   2. While BFS finds an augmenting path s→t in the residual graph:
 *      a. Find the bottleneck (minimum residual capacity on the path).
 *      b. Update residual capacities: subtract along forward edges,
 *         add along reverse edges.
 *      c. Accumulate the bottleneck into total max flow.
 *   3. Compute flow[i][j] = capacity[i][j] − residual[i][j] for each edge.
 *
 * Time Complexity: O(V * E²)
 *   - At most O(V * E) augmenting paths (BFS shortest-path guarantee).
 *   - Each BFS takes O(V + E) = O(E) time.
 *
 * Parameters:
 *   capacity — capacity[i][j] = bandwidth of directed link i→j (0 if none)
 *   n        — number of nodes in the network (must be <= MAX_HOSTS)
 *   source   — index of the source node
 *   sink     — index of the sink node
 *   flow     — output: flow[i][j] = actual flow assigned to edge i→j
 *
 * Returns:
 *   The maximum flow value.
 */
int fordFulkerson(int capacity[][MAX_HOSTS], int n,
                  int source, int sink,
                  int flow[][MAX_HOSTS])
{
    /* Build the residual graph as a copy of the capacity matrix */
    int residual[MAX_HOSTS][MAX_HOSTS];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            residual[i][j] = capacity[i][j];
        }
    }

    int parent[MAX_HOSTS];
    int max_flow = 0;

    /* Repeatedly find augmenting paths via BFS */
    while (bfs(residual, n, source, sink, parent)) {

        /* Find the bottleneck capacity along the path s ~> t */
        int path_flow = INT_MAX;
        for (int v = sink; v != source; v = parent[v]) {
            int u = parent[v];
            if (residual[u][v] < path_flow) {
                path_flow = residual[u][v];
            }
        }

        /* Update residual capacities along the path:
         *   - Subtract path_flow from forward edges (consume capacity)
         *   - Add path_flow to reverse edges (allow flow cancellation)
         */
        for (int v = sink; v != source; v = parent[v]) {
            int u = parent[v];
            residual[u][v] -= path_flow;
            residual[v][u] += path_flow;
        }

        max_flow += path_flow;
    }

    /* Compute the actual flow on each edge:
     *   flow[i][j] = capacity[i][j] − residual[i][j]
     *   (only for original forward edges where capacity > 0)
     */
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (capacity[i][j] > 0) {
                flow[i][j] = capacity[i][j] - residual[i][j];
            } else {
                flow[i][j] = 0;
            }
        }
    }

    return max_flow;
}

/* ============================================================================
 * PRINT FLOW NETWORK
 * ============================================================================
 *
 * Displays a formatted summary of each edge in the flow network, showing
 * the capacity, actual flow, and utilization percentage for every link
 * that has nonzero capacity.
 *
 * Cybersecurity Domain Mapping:
 *   Visualizes bandwidth utilization across all network links so that
 *   SOC operators can identify saturated links (bottlenecks) and
 *   underutilized paths.
 *
 * Time Complexity: O(V²) — iterates over all possible edges
 *
 * Parameters:
 *   capacity — original capacity matrix
 *   flow     — flow matrix (from fordFulkerson)
 *   n        — number of nodes
 *   names    — human-readable names for each node
 */
void printFlowNetwork(int capacity[][MAX_HOSTS], int flow[][MAX_HOSTS],
                      int n, char names[][32])
{
    printf("  %-22s -> %-22s  %8s  %8s  %s\n",
           "From", "To", "Capacity", "Flow", "Utilization");
    printf("  ");
    for (int i = 0; i < 82; i++) printf("-");
    printf("\n");

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (capacity[i][j] > 0) {
                double util = (capacity[i][j] > 0)
                    ? (100.0 * flow[i][j] / capacity[i][j])
                    : 0.0;
                const char *bar;
                if (util >= 100.0)      bar = "[SATURATED]";
                else if (util >= 75.0)  bar = "[HIGH]";
                else if (util >= 50.0)  bar = "[MODERATE]";
                else if (util > 0.0)    bar = "[LOW]";
                else                    bar = "[IDLE]";

                printf("  %-22s -> %-22s  %5d     %5d     %5.1f%% %s\n",
                       names[i], names[j],
                       capacity[i][j], flow[i][j], util, bar);
            }
        }
    }
}

/* ============================================================================
 * MAXIMUM BIPARTITE MATCHING (via reduction to Max-Flow)
 * ============================================================================
 *
 * Finds the maximum cardinality matching in a bipartite graph by reducing
 * the problem to maximum flow:
 *
 *   1. Construct a flow network with N = numAnalysts + numIncidents + 2 nodes:
 *        - Node 0: super-source
 *        - Nodes 1..numAnalysts: analyst nodes
 *        - Nodes numAnalysts+1..numAnalysts+numIncidents: incident nodes
 *        - Node N-1: super-sink
 *   2. Add edges:
 *        - super-source → each analyst with capacity 1
 *        - analyst i → incident j with capacity 1 (if compatible)
 *        - each incident → super-sink with capacity 1
 *   3. Run Ford-Fulkerson on this network.
 *   4. Extract matching: for each analyst node, check which incident node
 *      has flow = 1 on the connecting edge.
 *
 * Cybersecurity Domain Mapping:
 *   Analyst-to-Incident Optimal Assignment — given N SOC analysts and M
 *   security incidents, with a compatibility matrix indicating which
 *   analysts have the skills to handle which incident types, this finds
 *   the maximum number of simultaneous 1:1 pairings. This ensures
 *   maximum incident coverage during a coordinated attack scenario.
 *
 * Time Complexity: O(V * E²) where V = numAnalysts + numIncidents + 2
 *   In practice, for bipartite matching, this is O((A+I) * A * I).
 *
 * Parameters:
 *   compatibility — compatibility[i][j] = 1 if analyst i can handle incident j
 *   numAnalysts   — number of analysts (left partition)
 *   numIncidents  — number of incidents (right partition)
 *   matching      — output: matching[i] = incident index for analyst i,
 *                   or -1 if unmatched
 *
 * Returns:
 *   Size of maximum matching (number of pairings).
 */
int maxBipartiteMatching(int compatibility[][MAX_HOSTS],
                         int numAnalysts, int numIncidents,
                         int matching[])
{
    /*
     * Node layout:
     *   0                               = super-source
     *   1 .. numAnalysts                 = analyst nodes
     *   numAnalysts+1 .. numAnalysts+numIncidents = incident nodes
     *   numAnalysts + numIncidents + 1   = super-sink
     */
    int totalNodes = numAnalysts + numIncidents + 2;
    int superSource = 0;
    int superSink   = totalNodes - 1;

    /* Build the capacity matrix for the flow network */
    int cap[MAX_HOSTS][MAX_HOSTS];
    memset(cap, 0, sizeof(cap));

    /* super-source → each analyst (capacity 1) */
    for (int i = 0; i < numAnalysts; i++) {
        cap[superSource][i + 1] = 1;
    }

    /* analyst i → incident j if compatible (capacity 1)
     * Analyst i is node (i + 1)
     * Incident j is node (numAnalysts + 1 + j)
     */
    for (int i = 0; i < numAnalysts; i++) {
        for (int j = 0; j < numIncidents; j++) {
            if (compatibility[i][j]) {
                cap[i + 1][numAnalysts + 1 + j] = 1;
            }
        }
    }

    /* each incident → super-sink (capacity 1) */
    for (int j = 0; j < numIncidents; j++) {
        cap[numAnalysts + 1 + j][superSink] = 1;
    }

    /* Run Ford-Fulkerson to compute max flow */
    int flowMatrix[MAX_HOSTS][MAX_HOSTS];
    int maxMatch = fordFulkerson(cap, totalNodes, superSource, superSink,
                                 flowMatrix);

    /* Extract matching from the flow result */
    for (int i = 0; i < numAnalysts; i++) {
        matching[i] = -1;  /* Default: unmatched */
        for (int j = 0; j < numIncidents; j++) {
            int analystNode  = i + 1;
            int incidentNode = numAnalysts + 1 + j;
            if (flowMatrix[analystNode][incidentNode] == 1) {
                matching[i] = j;
                break;
            }
        }
    }

    return maxMatch;
}

/* ============================================================================
 * PRINT MATCHING
 * ============================================================================
 *
 * Displays the analyst-to-incident matching result in a formatted table.
 *
 * Cybersecurity Domain Mapping:
 *   Provides a clear operational display of SOC analyst assignments for
 *   incident response coordination.
 *
 * Time Complexity: O(numAnalysts)
 *
 * Parameters:
 *   matching      — matching[i] = incident index or -1
 *   numAnalysts   — number of analysts
 *   analystNames  — display names for analysts
 *   incidentNames — display names for incidents
 */
void printMatching(int matching[], int numAnalysts,
                   char analystNames[][32], char incidentNames[][64])
{
    printf("  %-5s  %-25s  %-10s  %s\n",
           "Slot", "Analyst", "Status", "Assigned Incident");
    printf("  ");
    for (int i = 0; i < 78; i++) printf("-");
    printf("\n");

    for (int i = 0; i < numAnalysts; i++) {
        if (matching[i] >= 0) {
            printf("  [%d]   %-25s  ASSIGNED    %s\n",
                   i, analystNames[i], incidentNames[matching[i]]);
        } else {
            printf("  [%d]   %-25s  STANDBY     (no assignment)\n",
                   i, analystNames[i]);
        }
    }
}

/* ============================================================================
 * DEMO DRIVER: run_flow_demos()
 * ============================================================================
 *
 * Demonstrates all network flow algorithms with cybersecurity-themed data.
 *
 * Demo 1: Ford-Fulkerson — 6-node network topology bandwidth analysis
 * Demo 2: Bipartite Matching — SOC analyst-to-incident assignment
 */
void run_flow_demos(void)
{
    printf("\n");
    printf("============================================================"
           "====================\n");
    printf("   NETWORK FLOW MODULE — Cybersecurity Threat Engine Demos\n");
    printf("============================================================"
           "====================\n");

    /* =================================================================
     * DEMO 1: Ford-Fulkerson — Maximum Network Bandwidth Allocation
     * =================================================================
     *
     * Network topology (6 nodes):
     *
     *   [0] Internet_Gateway (SOURCE)
     *       |-- 16 --> [1] Firewall
     *       |-- 13 --> [2] DMZ_Server
     *
     *   [1] Firewall
     *       |-- 10 --> [2] DMZ_Server
     *       |-- 12 --> [3] App_Server
     *       |--  4 --> [4] Load_Balancer
     *
     *   [2] DMZ_Server
     *       |-- 14 --> [4] Load_Balancer
     *       |--  9 --> [1] Firewall  (feedback link)
     *
     *   [3] App_Server
     *       |-- 20 --> [5] Database (SINK)
     *       |--  7 --> [2] DMZ_Server
     *
     *   [4] Load_Balancer
     *       |--  4 --> [3] App_Server
     *       |--  4 --> [5] Database (SINK)
     */
    printf("\n");
    printf("============================================================"
           "====================\n");
    printf("  DEMO 1: Ford-Fulkerson (Edmonds-Karp) — Max Bandwidth"
           " Allocation\n");
    printf("============================================================"
           "====================\n\n");

    printf("  SCENARIO: Determine maximum data throughput from Internet"
           " Gateway\n");
    printf("  to the critical Database server through a multi-hop"
           " enterprise network.\n");
    printf("  Each link has a limited bandwidth capacity (Mbps).\n\n");

    int capacity[MAX_HOSTS][MAX_HOSTS];
    memset(capacity, 0, sizeof(capacity));

    char names[MAX_HOSTS][32];
    strcpy(names[0], "Internet_Gateway");
    strcpy(names[1], "Firewall");
    strcpy(names[2], "DMZ_Server");
    strcpy(names[3], "App_Server");
    strcpy(names[4], "Load_Balancer");
    strcpy(names[5], "Database");

    int n = 6;

    /* Define link capacities (Mbps) */
    capacity[0][1] = 16;   /* Internet_Gateway → Firewall       */
    capacity[0][2] = 13;   /* Internet_Gateway → DMZ_Server     */
    capacity[1][2] = 10;   /* Firewall         → DMZ_Server     */
    capacity[1][3] = 12;   /* Firewall         → App_Server     */
    capacity[1][4] =  4;   /* Firewall         → Load_Balancer  */
    capacity[2][1] =  9;   /* DMZ_Server       → Firewall (rev) */
    capacity[2][4] = 14;   /* DMZ_Server       → Load_Balancer  */
    capacity[3][2] =  7;   /* App_Server       → DMZ_Server     */
    capacity[3][5] = 20;   /* App_Server       → Database       */
    capacity[4][3] =  4;   /* Load_Balancer    → App_Server     */
    capacity[4][5] =  4;   /* Load_Balancer    → Database       */

    printf("  Network Topology (link capacities in Mbps):\n\n");
    printf("    [Internet_Gateway]--16-->[Firewall]--12-->[App_Server]"
           "--20-->[Database]\n");
    printf("           |                  |    ^             |"
           "               ^\n");
    printf("           13                 10   9             7"
           "               4\n");
    printf("           |                  |    |             |"
           "               |\n");
    printf("           v                  v    |             v"
           "               |\n");
    printf("        [DMZ_Server]---------14-------->[Load_Balancer]\n");
    printf("                          [Firewall]--4-->[Load_Balancer]\n");
    printf("                          [Load_Balancer]--4-->[App_Server]\n\n");

    int flow[MAX_HOSTS][MAX_HOSTS];
    memset(flow, 0, sizeof(flow));

    int max_flow = fordFulkerson(capacity, n, 0, 5, flow);

    printf("  Per-Link Bandwidth Utilization:\n\n");
    printFlowNetwork(capacity, flow, n, names);

    printf("\n  +------------------------------------------------------+\n");
    printf("  | RESULT: Maximum throughput = %d Mbps                  |\n",
           max_flow);
    printf("  +------------------------------------------------------+\n");
    printf("\n  INTERPRETATION:\n");
    printf("    The maximum data flow that can be routed from the Internet\n");
    printf("    Gateway to the Database is %d Mbps. Links marked [SATURATED]\n",
           max_flow);
    printf("    are bottlenecks — upgrading them would increase throughput.\n");
    printf("    During a DDoS attack, adversaries would need to push >"
           " %d Mbps\n", max_flow);
    printf("    to overwhelm the path to the Database.\n");

    /* =================================================================
     * DEMO 2: Bipartite Matching — Analyst-to-Incident Assignment
     * ================================================================= */
    printf("\n\n");
    printf("============================================================"
           "====================\n");
    printf("  DEMO 2: Maximum Bipartite Matching — Analyst-Incident"
           " Assignment\n");
    printf("============================================================"
           "====================\n\n");

    printf("  SCENARIO: A coordinated attack has triggered 5 security"
           " incidents.\n");
    printf("  5 SOC analysts are available, each with different skill"
           " sets.\n");
    printf("  Find the maximum number of 1:1 analyst-incident pairings.\n\n");

    int numAnalysts  = 5;
    int numIncidents = 5;

    char analystNames[MAX_HOSTS][32];
    strcpy(analystNames[0], "Alice (Malware)");
    strcpy(analystNames[1], "Bob (Network)");
    strcpy(analystNames[2], "Carol (Forensics)");
    strcpy(analystNames[3], "Dave (AppSec)");
    strcpy(analystNames[4], "Eve (Threat Intel)");

    char incidentNames[MAX_HOSTS][64];
    strcpy(incidentNames[0], "INC-001: Ransomware Outbreak");
    strcpy(incidentNames[1], "INC-002: DDoS on Web Portal");
    strcpy(incidentNames[2], "INC-003: Data Exfiltration");
    strcpy(incidentNames[3], "INC-004: SQL Injection Attack");
    strcpy(incidentNames[4], "INC-005: Phishing Campaign");

    /*
     * Compatibility matrix:
     *                          INC-001 INC-002 INC-003 INC-004 INC-005
     * Alice  (Malware)   :       1       0       1       0       1
     * Bob    (Network)   :       0       1       0       0       0
     * Carol  (Forensics) :       1       0       1       0       0
     * Dave   (AppSec)    :       0       0       0       1       1
     * Eve    (Threat Intel):     0       1       1       0       1
     */
    int compat[MAX_HOSTS][MAX_HOSTS];
    memset(compat, 0, sizeof(compat));

    compat[0][0] = 1; compat[0][2] = 1; compat[0][4] = 1;   /* Alice  */
    compat[1][1] = 1;                                         /* Bob    */
    compat[2][0] = 1; compat[2][2] = 1;                       /* Carol  */
    compat[3][3] = 1; compat[3][4] = 1;                       /* Dave   */
    compat[4][1] = 1; compat[4][2] = 1; compat[4][4] = 1;    /* Eve    */

    printf("  Skill Compatibility Matrix:\n\n");
    printf("  %-25s", "Analyst");
    for (int j = 0; j < numIncidents; j++) {
        printf("  INC-%03d", j + 1);
    }
    printf("\n  ");
    for (int k = 0; k < 25 + numIncidents * 8; k++) printf("-");
    printf("\n");

    for (int i = 0; i < numAnalysts; i++) {
        printf("  %-25s", analystNames[i]);
        for (int j = 0; j < numIncidents; j++) {
            printf("    %s", compat[i][j] ? " YES" : "  - ");
        }
        printf("\n");
    }
    printf("\n");

    int matching[MAX_HOSTS];
    int matchSize = maxBipartiteMatching(compat, numAnalysts, numIncidents,
                                         matching);

    printf("  Optimal Assignment Result:\n\n");
    printMatching(matching, numAnalysts, analystNames, incidentNames);

    printf("\n  +------------------------------------------------------+\n");
    printf("  | RESULT: Maximum pairings = %d / %d incidents covered",
           matchSize, numIncidents);
    if (numIncidents - matchSize > 0) {
        printf("  |\n");
    } else {
        printf("    |\n");
    }
    printf("  +------------------------------------------------------+\n");

    printf("\n  INTERPRETATION:\n");
    printf("    %d out of %d incidents can be assigned a qualified analyst.\n",
           matchSize, numIncidents);
    if (matchSize < numIncidents) {
        printf("    %d incident(s) remain unassigned and need escalation or\n",
               numIncidents - matchSize);
        printf("    cross-training of analysts to expand coverage.\n");
    } else {
        printf("    Full coverage achieved — all incidents have a dedicated"
               " analyst.\n");
    }

    printf("\n============================================================"
           "====================\n");
    printf("   END OF NETWORK FLOW DEMOS\n");
    printf("============================================================"
           "====================\n\n");
}
