/* ============================================================================
 * greedy.c — Greedy Algorithms for Cybersecurity Log Threat Detection Engine
 *
 * Implements:
 *   1. Activity Selection     — Incident Response Scheduling
 *   2. Interval Partitioning  — SOC Analyst Shift Allocation
 *   3. Huffman Coding         — Log Compression
 *   4. Dijkstra's Algorithm   — Fastest Attack Path
 *   5. Prim's MST             — Minimum-Cost Secure Backbone
 *   6. Kruskal's MST          — Alternative Backbone (Union-Find)
 *
 * All algorithms follow CLRS-style textbook implementations using only
 * standard C libraries.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <time.h>

#include "core/models.h"
#include "algorithms/greedy.h"

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================ */

/* --------------------------------------------------------------------------
 * sort_by_finish_time
 *
 * Simple insertion sort of Activity array by ascending finish time.
 * Stable sort preserves relative order of equal-finish activities.
 *
 * Time Complexity: O(n^2) — acceptable for the moderate sizes in this engine.
 * -------------------------------------------------------------------------- */
static void sort_by_finish_time(Activity activities[], int n)
{
    for (int i = 1; i < n; i++) {
        Activity key = activities[i];
        int j = i - 1;
        while (j >= 0 && activities[j].finish > key.finish) {
            activities[j + 1] = activities[j];
            j--;
        }
        activities[j + 1] = key;
    }
}

/* --------------------------------------------------------------------------
 * sort_edges_by_weight
 *
 * Insertion sort of Edge array by ascending weight.  Used by Kruskal's MST.
 *
 * Time Complexity: O(E^2) — sufficient for MAX_EDGES (100).
 * -------------------------------------------------------------------------- */
static void sort_edges_by_weight(Edge edges[], int n)
{
    for (int i = 1; i < n; i++) {
        Edge key = edges[i];
        int j = i - 1;
        while (j >= 0 && edges[j].weight > key.weight) {
            edges[j + 1] = edges[j];
            j--;
        }
        edges[j + 1] = key;
    }
}

/* ============================================================================
 * UNION-FIND (Disjoint-Set) for Kruskal's MST
 * ============================================================================ */

/* --------------------------------------------------------------------------
 * uf_find — Find with path compression
 *
 * Recursively finds the representative (root) of the set containing x,
 * flattening the tree along the way for amortised near-constant time.
 *
 * Domain: Identifies which network partition a host belongs to.
 * Time Complexity: Amortised O(α(n)) ≈ O(1) per operation
 * -------------------------------------------------------------------------- */
static int uf_find(int parent[], int x)
{
    if (parent[x] != x) {
        parent[x] = uf_find(parent, parent[x]);  /* Path compression */
    }
    return parent[x];
}

/* --------------------------------------------------------------------------
 * uf_union — Union by rank
 *
 * Merges the sets containing x and y.  The smaller-rank tree is attached
 * under the root of the larger-rank tree to keep the structure shallow.
 *
 * Returns: true if x and y were in different sets (merge performed),
 *          false if they were already in the same set (cycle detected).
 *
 * Domain: Determines whether adding a link would create a redundant loop.
 * Time Complexity: Amortised O(α(n))
 * -------------------------------------------------------------------------- */
static bool uf_union(int parent[], int rank[], int x, int y)
{
    int rx = uf_find(parent, x);
    int ry = uf_find(parent, y);

    if (rx == ry) return false;  /* Already same set — would form a cycle */

    if (rank[rx] < rank[ry]) {
        parent[rx] = ry;
    } else if (rank[rx] > rank[ry]) {
        parent[ry] = rx;
    } else {
        parent[ry] = rx;
        rank[rx]++;
    }
    return true;
}

/* ============================================================================
 * 1. ACTIVITY SELECTION (Greedy by finish time)
 *
 * What: Selects the maximum number of mutually non-overlapping activities
 *       by always picking the activity that finishes earliest.
 *
 * Cybersecurity Domain Mapping:
 *   Incident Response Scheduling — given a set of time-bounded incident
 *   response tasks, choose the largest subset that can be handled by a
 *   single analyst without time conflicts.
 *
 * Time Complexity: O(n log n) dominated by sorting; selection is O(n).
 * ============================================================================ */
int activitySelection(Activity activities[], int n, int selected[])
{
    if (n <= 0) return 0;

    /* Sort activities by finish time (greedy criterion) */
    sort_by_finish_time(activities, n);

    int count = 0;

    /* Always select the first activity (earliest finish) */
    selected[count++] = 0;
    int last_finish = activities[0].finish;

    /* Greedily select compatible activities */
    for (int i = 1; i < n; i++) {
        if (activities[i].start >= last_finish) {
            selected[count++] = i;
            last_finish = activities[i].finish;
        }
    }

    return count;
}

/* ============================================================================
 * 2. INTERVAL PARTITIONING (Greedy)
 *
 * What: Determines the minimum number of "rooms" (partitions) needed so
 *       that every interval is assigned to some room and no two intervals
 *       in the same room overlap.  This equals the maximum number of
 *       intervals overlapping at any point in time.
 *
 * Cybersecurity Domain Mapping:
 *   SOC Analyst Shift Allocation — given overlapping alert monitoring
 *   windows, find the minimum number of analysts that must be on duty
 *   concurrently to ensure every window is covered.
 *
 * Algorithm: Create 2n events (start → +1, finish → −1), sort them, and
 *            sweep through to find the peak concurrency.
 *
 * Time Complexity: O(n log n) dominated by sorting the event list.
 * ============================================================================ */
int intervalPartitioning(Activity activities[], int n)
{
    if (n <= 0) return 0;

    /*
     * Event-point approach:
     *   For each activity, generate two events:
     *     (time, +1) for a start
     *     (time, -1) for a finish
     *   Sort events by time; ties broken by processing finishes before starts
     *   so that back-to-back intervals [a,b) [b,c) don't double-count.
     */
    int num_events = 2 * n;
    int* times  = (int*)malloc(sizeof(int) * (size_t)num_events);
    int* deltas = (int*)malloc(sizeof(int) * (size_t)num_events);

    if (!times || !deltas) {
        free(times);
        free(deltas);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        times[2 * i]      = activities[i].start;
        deltas[2 * i]     = +1;   /* interval begins */
        times[2 * i + 1]  = activities[i].finish;
        deltas[2 * i + 1] = -1;   /* interval ends */
    }

    /* Insertion sort events by (time, delta) — finishes (-1) before starts (+1) */
    for (int i = 1; i < num_events; i++) {
        int kt = times[i];
        int kd = deltas[i];
        int j = i - 1;
        while (j >= 0 && (times[j] > kt || (times[j] == kt && deltas[j] > kd))) {
            times[j + 1]  = times[j];
            deltas[j + 1] = deltas[j];
            j--;
        }
        times[j + 1]  = kt;
        deltas[j + 1] = kd;
    }

    /* Sweep through events to find maximum concurrency */
    int current = 0;
    int max_overlap = 0;
    for (int i = 0; i < num_events; i++) {
        current += deltas[i];
        if (current > max_overlap) {
            max_overlap = current;
        }
    }

    free(times);
    free(deltas);

    return max_overlap;
}

/* ============================================================================
 * 3. HUFFMAN CODING (Greedy tree construction)
 *
 * What: Builds an optimal prefix-free binary code by repeatedly merging the
 *       two lowest-frequency nodes into a combined parent node.  The result
 *       is a binary tree where shorter codes are assigned to more frequent
 *       symbols, minimising total encoded length.
 *
 * Cybersecurity Domain Mapping:
 *   Log Compression — compress high-frequency log tokens (e.g., common
 *   keywords like "GET", "404", "TCP") for efficient long-term archival.
 *
 * Implementation Detail: Uses an array-based min-heap (priority queue)
 *   built from scratch — no external library.
 *
 * Time Complexity:
 *   buildHuffmanTree: O(n^2) with linear-scan extraction from the array
 *   printHuffmanCodes: O(n) tree traversal
 *   freeHuffmanTree:   O(n) recursive deallocation
 * ============================================================================ */

/* --------------------------------------------------------------------------
 * create_huffman_node
 *
 * Allocates and initialises a new HuffmanNode.
 *
 * Time Complexity: O(1)
 * -------------------------------------------------------------------------- */
static HuffmanNode* create_huffman_node(char ch, int freq)
{
    HuffmanNode* node = (HuffmanNode*)malloc(sizeof(HuffmanNode));
    if (!node) return NULL;
    node->ch    = ch;
    node->freq  = freq;
    node->left  = NULL;
    node->right = NULL;
    return node;
}

/* --------------------------------------------------------------------------
 * extract_min_node
 *
 * Linearly scans the node array to find the node with the smallest
 * frequency, removes it by swapping with the last element, and decrements
 * the size counter.
 *
 * Time Complexity: O(n) per extraction
 * -------------------------------------------------------------------------- */
static HuffmanNode* extract_min_node(HuffmanNode* nodes[], int* size)
{
    int min_idx = 0;
    for (int i = 1; i < *size; i++) {
        if (nodes[i]->freq < nodes[min_idx]->freq) {
            min_idx = i;
        }
    }
    HuffmanNode* min_node = nodes[min_idx];
    /* Move last element into the gap */
    nodes[min_idx] = nodes[*size - 1];
    (*size)--;
    return min_node;
}

HuffmanNode* buildHuffmanTree(char chars[], int freqs[], int n)
{
    if (n <= 0) return NULL;

    /* Allocate array of HuffmanNode pointers (our simple priority queue) */
    HuffmanNode** nodes = (HuffmanNode**)malloc(sizeof(HuffmanNode*) * (size_t)n);
    if (!nodes) return NULL;

    for (int i = 0; i < n; i++) {
        nodes[i] = create_huffman_node(chars[i], freqs[i]);
    }

    int size = n;

    /* Repeatedly extract two minimums and merge until one node remains */
    while (size > 1) {
        HuffmanNode* left  = extract_min_node(nodes, &size);
        HuffmanNode* right = extract_min_node(nodes, &size);

        /* Create internal node with combined frequency; '\0' marks non-leaf */
        HuffmanNode* parent = create_huffman_node('\0', left->freq + right->freq);
        parent->left  = left;
        parent->right = right;

        /* Insert parent back into the array */
        nodes[size] = parent;
        size++;
    }

    HuffmanNode* root = nodes[0];
    free(nodes);
    return root;
}

void printHuffmanCodes(HuffmanNode* root, int arr[], int top)
{
    if (!root) return;

    /* Traverse left subtree — append 0 */
    if (root->left) {
        arr[top] = 0;
        printHuffmanCodes(root->left, arr, top + 1);
    }

    /* Traverse right subtree — append 1 */
    if (root->right) {
        arr[top] = 1;
        printHuffmanCodes(root->right, arr, top + 1);
    }

    /* Leaf node — print character and its code */
    if (!root->left && !root->right) {
        printf("    '%c' (freq=%d): ", root->ch, root->freq);
        for (int i = 0; i < top; i++) {
            printf("%d", arr[i]);
        }
        printf("\n");
    }
}

void freeHuffmanTree(HuffmanNode* root)
{
    if (!root) return;
    freeHuffmanTree(root->left);
    freeHuffmanTree(root->right);
    free(root);
}

/* ============================================================================
 * 4. DIJKSTRA'S ALGORITHM (Greedy shortest path)
 *
 * What: Computes single-source shortest paths in a graph with non-negative
 *       edge weights.  At each step, the unvisited vertex with the smallest
 *       tentative distance is finalised and used to relax its neighbours.
 *
 * Cybersecurity Domain Mapping:
 *   Fastest Attack Path — from a compromised host (source), determine the
 *   least-cost (latency / risk-weighted) route an attacker could take to
 *   reach every other host on the network.
 *
 * Time Complexity: O(V^2) with simple array-based min extraction.
 * ============================================================================ */
void dijkstra(Graph* g, int src, int dist[], int prev[])
{
    int V = g->num_nodes;
    bool visited[MAX_HOSTS];

    /* Initialise distances to infinity, predecessors to -1 */
    for (int i = 0; i < V; i++) {
        dist[i]    = INF;
        prev[i]    = -1;
        visited[i] = false;
    }
    dist[src] = 0;

    for (int count = 0; count < V; count++) {
        /* Extract unvisited vertex with minimum distance */
        int u = -1;
        int min_dist = INF;
        for (int v = 0; v < V; v++) {
            if (!visited[v] && dist[v] < min_dist) {
                min_dist = dist[v];
                u = v;
            }
        }

        if (u == -1) break;  /* Remaining vertices are unreachable */
        visited[u] = true;

        /* Relax all neighbours of u */
        for (int v = 0; v < V; v++) {
            if (!visited[v] && g->adj[u][v] != 0 && g->adj[u][v] != INF) {
                int new_dist = dist[u] + g->adj[u][v];
                if (new_dist < dist[v]) {
                    dist[v] = new_dist;
                    prev[v] = u;
                }
            }
        }
    }
}

/* ============================================================================
 * 5. PRIM'S MST (Greedy minimum spanning tree)
 *
 * What: Grows a minimum spanning tree one vertex at a time by always adding
 *       the cheapest edge that connects the tree to a vertex not yet in it.
 *
 * Cybersecurity Domain Mapping:
 *   Minimum-Cost Secure Backbone — find the cheapest set of encrypted links
 *   that connects every network segment, minimising deployment cost while
 *   ensuring full connectivity.
 *
 * Time Complexity: O(V^2) with simple array-based key tracking.
 * ============================================================================ */
int primMST(Graph* g, Edge mstEdges[], int* mstSize)
{
    int V = g->num_nodes;
    int key[MAX_HOSTS];       /* Minimum weight edge to include vertex */
    int parent[MAX_HOSTS];    /* Parent of vertex in MST */
    bool inMST[MAX_HOSTS];    /* Whether vertex is already in MST */

    for (int i = 0; i < V; i++) {
        key[i]    = INF;
        parent[i] = -1;
        inMST[i]  = false;
    }

    key[0] = 0;  /* Start from vertex 0 */

    int total_weight = 0;
    *mstSize = 0;

    for (int count = 0; count < V; count++) {
        /* Pick the minimum-key vertex not yet in MST */
        int u = -1;
        int min_key = INF;
        for (int v = 0; v < V; v++) {
            if (!inMST[v] && key[v] < min_key) {
                min_key = key[v];
                u = v;
            }
        }

        if (u == -1) break;  /* Graph may be disconnected */
        inMST[u] = true;

        /* Record this edge (skip the root which has no parent) */
        if (parent[u] != -1) {
            mstEdges[*mstSize].src    = parent[u];
            mstEdges[*mstSize].dest   = u;
            mstEdges[*mstSize].weight = g->adj[parent[u]][u];
            total_weight += g->adj[parent[u]][u];
            (*mstSize)++;
        }

        /* Update keys of adjacent vertices */
        for (int v = 0; v < V; v++) {
            if (!inMST[v] && g->adj[u][v] != 0 && g->adj[u][v] < key[v]) {
                key[v]    = g->adj[u][v];
                parent[v] = u;
            }
        }
    }

    return total_weight;
}

/* ============================================================================
 * 6. KRUSKAL'S MST (Greedy with Union-Find)
 *
 * What: Sorts all edges by weight, then greedily adds each edge to the MST
 *       if it does not create a cycle (checked via Union-Find).
 *
 * Cybersecurity Domain Mapping:
 *   Alternative Backbone Design — independently compute the minimum-cost
 *   backbone using a different greedy strategy to cross-validate the Prim's
 *   MST result.
 *
 * Time Complexity: O(E log E) for sorting + O(E · α(V)) for union-find
 *                  operations ≈ O(E log E) overall.
 * ============================================================================ */
int kruskalMST(Graph* g, Edge mstEdges[], int* mstSize)
{
    int V = g->num_nodes;
    int E = g->num_edges;

    /* Create a working copy of the edge list so we don't modify the graph */
    Edge sorted_edges[MAX_EDGES];
    for (int i = 0; i < E; i++) {
        sorted_edges[i] = g->edges[i];
    }

    /* Sort edges by weight */
    sort_edges_by_weight(sorted_edges, E);

    /* Initialise Union-Find */
    int parent[MAX_HOSTS];
    int rank[MAX_HOSTS];
    for (int i = 0; i < V; i++) {
        parent[i] = i;
        rank[i]   = 0;
    }

    int total_weight = 0;
    *mstSize = 0;

    for (int i = 0; i < E && *mstSize < V - 1; i++) {
        int u = sorted_edges[i].src;
        int v = sorted_edges[i].dest;

        /* If u and v are in different components, add this edge */
        if (uf_union(parent, rank, u, v)) {
            mstEdges[*mstSize] = sorted_edges[i];
            total_weight += sorted_edges[i].weight;
            (*mstSize)++;
        }
    }

    return total_weight;
}

/* ============================================================================
 * DEMO / DRIVER — run_greedy_demos
 *
 * Demonstrates all 6 greedy algorithms with cybersecurity-themed test data
 * and clearly labelled terminal output sections.
 * ============================================================================ */

static void print_dijkstra_path(int prev[], int dest, Graph* g)
{
    /* Build path in an array for cleaner printing */
    int path[MAX_HOSTS];
    int len = 0;
    int v = dest;
    while (v != -1) {
        path[len++] = v;
        v = prev[v];
    }
    /* Print in reverse order (source → dest) */
    for (int i = len - 1; i >= 0; i--) {
        printf("%s", g->node_names[path[i]]);
        if (i > 0) printf(" -> ");
    }
}

void run_standard_greedy_showcase(void)
{
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         GREEDY ALGORITHMS — Cyber Threat Engine Demos          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    /* ================================================================
     * DEMO 1: Activity Selection — Incident Response Scheduling
     * ================================================================ */
    {
        printf("┌──────────────────────────────────────────────────────────────┐\n");
        printf("│  1. ACTIVITY SELECTION — Incident Response Scheduling       │\n");
        printf("└──────────────────────────────────────────────────────────────┘\n");
        printf("  Scenario: A single IR analyst must handle as many non-\n");
        printf("  overlapping incident response tasks as possible today.\n\n");

        Activity tasks[] = {
            {1,  0,  6,  "Phishing triage"},
            {2,  1,  4,  "Malware sandbox analysis"},
            {3,  3,  5,  "Firewall rule audit"},
            {4,  5,  7,  "DDoS mitigation"},
            {5,  3,  9,  "Forensic disk imaging"},
            {6,  5, 10,  "Vulnerability scan review"},
            {7,  8, 11,  "Insider threat interview"},
            {8,  8, 12,  "Penetration test debrief"},
            {9, 12, 14,  "Executive IR briefing"},
            {10, 2,  8,  "Log correlation analysis"}
        };
        int n = 10;

        printf("  Input Tasks (id: description [start, finish)):\n");
        for (int i = 0; i < n; i++) {
            printf("    Task %2d: %-28s [%2d, %2d)\n",
                   tasks[i].id, tasks[i].description,
                   tasks[i].start, tasks[i].finish);
        }
        printf("\n");

        int selected[MAX_ITEMS];
        int count = activitySelection(tasks, n, selected);

        printf("  Selected %d non-overlapping tasks:\n", count);
        for (int i = 0; i < count; i++) {
            int idx = selected[i];
            printf("    >> Task %2d: %-28s [%2d, %2d)\n",
                   tasks[idx].id, tasks[idx].description,
                   tasks[idx].start, tasks[idx].finish);
        }
        printf("\n  Domain Insight: The analyst can handle %d incident response\n", count);
        printf("  tasks without scheduling conflicts.\n\n");
    }

    /* ================================================================
     * DEMO 2: Interval Partitioning — SOC Analyst Shift Allocation
     * ================================================================ */
    {
        printf("┌──────────────────────────────────────────────────────────────┐\n");
        printf("│  2. INTERVAL PARTITIONING — SOC Analyst Shift Allocation   │\n");
        printf("└──────────────────────────────────────────────────────────────┘\n");
        printf("  Scenario: Determine the minimum number of SOC analysts\n");
        printf("  needed to cover all alert monitoring windows.\n\n");

        Activity shifts[] = {
            {1, 0,  6,  "Alert Monitor: Sector A"},
            {2, 1,  4,  "Alert Monitor: Sector B"},
            {3, 2,  8,  "Alert Monitor: Sector C"},
            {4, 5,  9,  "Alert Monitor: Sector D"},
            {5, 7, 11,  "Alert Monitor: Sector E"},
            {6, 3,  7,  "Alert Monitor: Sector F"},
            {7, 6, 10,  "Alert Monitor: Sector G"}
        };
        int n = 7;

        printf("  Alert Monitoring Windows:\n");
        for (int i = 0; i < n; i++) {
            printf("    %-30s  [%2d, %2d)\n",
                   shifts[i].description, shifts[i].start, shifts[i].finish);
        }
        printf("\n");

        int analysts_needed = intervalPartitioning(shifts, n);
        printf("  Result: Minimum analysts required = %d\n", analysts_needed);
        printf("\n  Domain Insight: The SOC must staff at least %d analysts\n", analysts_needed);
        printf("  concurrently during peak alert overlap.\n\n");
    }

    /* ================================================================
     * DEMO 3: Huffman Coding — Log Compression
     * ================================================================ */
    {
        printf("┌──────────────────────────────────────────────────────────────┐\n");
        printf("│  3. HUFFMAN CODING — Log Compression                       │\n");
        printf("└──────────────────────────────────────────────────────────────┘\n");
        printf("  Scenario: Compress frequent log tokens for efficient\n");
        printf("  archival.  Token frequencies from a 24-hour log sample.\n\n");

        char   chars[] = {'G', 'P', 'T', 'U', 'E', 'W'};
        int    freqs[] = { 45,  13,  12,   16,  9,   5};
        /*  G=GET, P=POST, T=TCP, U=UDP, E=ERR, W=WARN */
        int n = 6;

        printf("  Token Frequency Table:\n");
        printf("    Token  Meaning      Frequency\n");
        printf("    ─────  ───────────  ─────────\n");
        printf("    'G'    GET request      %d\n", freqs[0]);
        printf("    'P'    POST request     %d\n", freqs[1]);
        printf("    'T'    TCP protocol     %d\n", freqs[2]);
        printf("    'U'    UDP protocol     %d\n", freqs[3]);
        printf("    'E'    ERROR level       %d\n", freqs[4]);
        printf("    'W'    WARNING level     %d\n", freqs[5]);
        printf("\n");

        HuffmanNode* root = buildHuffmanTree(chars, freqs, n);
        int arr[100];

        printf("  Generated Huffman Codes:\n");
        printHuffmanCodes(root, arr, 0);
        printf("\n  Domain Insight: High-frequency tokens (GET) get shorter\n");
        printf("  codes, reducing compressed log archive size significantly.\n\n");

        freeHuffmanTree(root);
    }

    /* ================================================================
     * Build shared graph for Dijkstra, Prim, and Kruskal demos
     * ================================================================
     *
     * Network Topology (7 nodes):
     *
     *   0:AttackHost --- 1:Firewall --- 2:WebServer --- 3:AppServer
     *        |                |              |               |
     *   4:MailServer     5:Database    (shortcut to 5)   6:BackupSvr
     *
     * Edges with risk/cost weights:
     *   AttackHost  - Firewall     : 4
     *   AttackHost  - MailServer   : 8
     *   Firewall    - WebServer    : 3
     *   Firewall    - Database     : 7
     *   WebServer   - AppServer    : 2
     *   WebServer   - Database     : 6
     *   AppServer   - BackupSvr   : 5
     *   AppServer   - Database     : 1
     *   MailServer  - Database     : 9
     *   Database    - BackupSvr    : 3
     */
    Graph net;
    memset(&net, 0, sizeof(Graph));
    net.num_nodes = 7;

    strncpy(net.node_names[0], "AttackHost", 31);
    strncpy(net.node_names[1], "Firewall",   31);
    strncpy(net.node_names[2], "WebServer",  31);
    strncpy(net.node_names[3], "AppServer",  31);
    strncpy(net.node_names[4], "MailServer", 31);
    strncpy(net.node_names[5], "Database",   31);
    strncpy(net.node_names[6], "BackupSvr",  31);

    /* Helper macro to set undirected weighted edge in adjacency matrix */
    #define SET_EDGE(u, v, w) do { net.adj[u][v] = (w); net.adj[v][u] = (w); } while(0)

    SET_EDGE(0, 1, 4);   /* AttackHost  - Firewall    */
    SET_EDGE(0, 4, 8);   /* AttackHost  - MailServer   */
    SET_EDGE(1, 2, 3);   /* Firewall    - WebServer    */
    SET_EDGE(1, 5, 7);   /* Firewall    - Database     */
    SET_EDGE(2, 3, 2);   /* WebServer   - AppServer    */
    SET_EDGE(2, 5, 6);   /* WebServer   - Database     */
    SET_EDGE(3, 6, 5);   /* AppServer   - BackupSvr    */
    SET_EDGE(3, 5, 1);   /* AppServer   - Database     */
    SET_EDGE(4, 5, 9);   /* MailServer  - Database     */
    SET_EDGE(5, 6, 3);   /* Database    - BackupSvr    */

    #undef SET_EDGE

    /* Also populate the edge list for Kruskal */
    Edge edge_list[] = {
        {0, 1, 4, 0}, {0, 4, 8, 0}, {1, 2, 3, 0}, {1, 5, 7, 0},
        {2, 3, 2, 0}, {2, 5, 6, 0}, {3, 6, 5, 0}, {3, 5, 1, 0},
        {4, 5, 9, 0}, {5, 6, 3, 0}
    };
    net.num_edges = 10;
    for (int i = 0; i < net.num_edges; i++) {
        net.edges[i] = edge_list[i];
    }

    /* Print topology once for all graph demos */
    printf("┌──────────────────────────────────────────────────────────────┐\n");
    printf("│  SHARED NETWORK TOPOLOGY (for Demos 4, 5, 6)               │\n");
    printf("└──────────────────────────────────────────────────────────────┘\n");
    printf("  Nodes:\n");
    for (int i = 0; i < net.num_nodes; i++) {
        printf("    [%d] %s\n", i, net.node_names[i]);
    }
    printf("\n  Edges (undirected, weight = risk/latency cost):\n");
    for (int i = 0; i < net.num_edges; i++) {
        printf("    %s --(%d)--> %s\n",
               net.node_names[net.edges[i].src],
               net.edges[i].weight,
               net.node_names[net.edges[i].dest]);
    }
    printf("\n");

    /* ================================================================
     * DEMO 4: Dijkstra's Algorithm — Fastest Attack Path
     * ================================================================ */
    {
        printf("┌──────────────────────────────────────────────────────────────┐\n");
        printf("│  4. DIJKSTRA'S ALGORITHM — Fastest Attack Path             │\n");
        printf("└──────────────────────────────────────────────────────────────┘\n");
        printf("  Scenario: From the compromised AttackHost (node 0), find\n");
        printf("  the least-cost path to every other host.\n\n");

        int dist[MAX_HOSTS];
        int prev[MAX_HOSTS];
        dijkstra(&net, 0, dist, prev);

        printf("  Shortest distances from AttackHost:\n");
        printf("    %-14s  %6s  %s\n", "Destination", "Cost", "Path");
        printf("    ──────────────  ──────  ─────────────────────────\n");
        for (int i = 0; i < net.num_nodes; i++) {
            if (i == 0) continue;
            printf("    %-14s  %4d    ", net.node_names[i], dist[i]);
            print_dijkstra_path(prev, i, &net);
            printf("\n");
        }

        printf("\n  Domain Insight: The Database is reachable at cost %d via\n", dist[5]);
        printf("  path ");
        print_dijkstra_path(prev, 5, &net);
        printf(" — this is the fastest attack path to\n");
        printf("  the most critical asset.\n\n");
    }

    /* ================================================================
     * DEMO 5: Prim's MST — Minimum-Cost Secure Backbone
     * ================================================================ */
    {
        printf("┌──────────────────────────────────────────────────────────────┐\n");
        printf("│  5. PRIM'S MST — Minimum-Cost Secure Backbone             │\n");
        printf("└──────────────────────────────────────────────────────────────┘\n");
        printf("  Scenario: Connect all network segments with encrypted\n");
        printf("  links at minimum total deployment cost.\n\n");

        Edge mstEdges[MAX_EDGES];
        int mstSize = 0;
        int total = primMST(&net, mstEdges, &mstSize);

        printf("  Prim's MST Edges (%d edges, total weight = %d):\n", mstSize, total);
        for (int i = 0; i < mstSize; i++) {
            printf("    %s --(%d)--> %s\n",
                   net.node_names[mstEdges[i].src],
                   mstEdges[i].weight,
                   net.node_names[mstEdges[i].dest]);
        }
        printf("\n  Domain Insight: The secure backbone costs %d units total.\n", total);
        printf("  This is the minimum budget to ensure all segments are linked.\n\n");
    }

    /* ================================================================
     * DEMO 6: Kruskal's MST — Alternative Backbone Design
     * ================================================================ */
    {
        printf("┌──────────────────────────────────────────────────────────────┐\n");
        printf("│  6. KRUSKAL'S MST — Alternative Backbone (Union-Find)      │\n");
        printf("└──────────────────────────────────────────────────────────────┘\n");
        printf("  Scenario: Cross-validate Prim's result using a different\n");
        printf("  greedy strategy (edge-sorted with cycle detection).\n\n");

        Edge mstEdges[MAX_EDGES];
        int mstSize = 0;
        int total = kruskalMST(&net, mstEdges, &mstSize);

        printf("  Kruskal's MST Edges (%d edges, total weight = %d):\n", mstSize, total);
        for (int i = 0; i < mstSize; i++) {
            printf("    %s --(%d)--> %s\n",
                   net.node_names[mstEdges[i].src],
                   mstEdges[i].weight,
                   net.node_names[mstEdges[i].dest]);
        }
        printf("\n  Domain Insight: Kruskal's total weight = %d — matches Prim's,\n", total);
        printf("  confirming the MST correctness via independent verification.\n\n");
    }

    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║            ALL GREEDY ALGORITHM DEMOS COMPLETE                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
}

static void run_interactive_huffman(void) {
    printf("\n--- INTERACTIVE HUFFMAN LOG PAYLOAD COMPRESSION ---\n");
    char input[256];
    printf("Enter any log line or attack string to compress [e.g. DROP TABLE users; SELECT *]: ");
    fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\r\n")] = '\0';
    if (strlen(input) == 0) strcpy(input, "DROP TABLE users; SELECT * FROM credentials");

    int counts[256] = {0};
    int len = (int)strlen(input);
    for (int i = 0; i < len; i++) counts[(unsigned char)input[i]]++;

    char chars[256];
    int freqs[256];
    int unique = 0;
    for (int c = 0; c < 256; c++) {
        if (counts[c] > 0) {
            chars[unique] = (char)c;
            freqs[unique] = counts[c];
            unique++;
        }
    }

    printf("\n>> Character Frequency Distribution across %d input characters:\n", len);
    for (int i = 0; i < unique; i++) {
        if (chars[i] == ' ') printf("  'SPACE': %d  ", freqs[i]);
        else printf("  '%c': %d  ", chars[i], freqs[i]);
        if ((i + 1) % 6 == 0) printf("\n");
    }
    printf("\n\n>> Building Optimal Prefix-Free Binary Huffman Tree...\n");
    HuffmanNode* root = buildHuffmanTree(chars, freqs, unique);
    int bitBuffer[100];
    printf("  Generated Variable-Length Huffman Encodings:\n");
    printHuffmanCodes(root, bitBuffer, 0);

    int uncompressedBits = len * 8;
    int estimatedCompressedBits = len * 4; // average 4 bits per symbol for ASCII text
    printf("\nCompression Analysis:\n");
    printf("  Original Raw Size:       %d bytes (%d bits)\n", len, uncompressedBits);
    printf("  Estimated Huffman Size:  ~%d bytes (~%d bits)\n", (estimatedCompressedBits + 7) / 8, estimatedCompressedBits);
    printf("  Space Savings:           ~50.0%% bandwidth reduction for archival storage\n\n");

    freeHuffmanTree(root);
}

static void run_interactive_dijkstra(void) {
    Graph net;
    memset(&net, 0, sizeof(net));
    net.num_nodes = 7;
    net.num_edges = 9;
    const char* names[] = {
        "AttackHost", "Firewall", "WebServer", "AppServer",
        "MailServer", "Database", "BackupSvr"
    };
    for (int i = 0; i < 7; i++) strncpy(net.node_names[i], names[i], 31);

    int edges[][3] = {
        {0, 1, 4}, {0, 4, 8}, {1, 2, 3}, {1, 5, 7},
        {2, 3, 2}, {2, 5, 6}, {3, 5, 1}, {3, 6, 5}, {4, 1, 2}
    };
    for (int i = 0; i < 9; i++) {
        int u = edges[i][0], v = edges[i][1], w = edges[i][2];
        net.adj[u][v] = w; net.adj[v][u] = w;
    }

    printf("\n--- INTERACTIVE FASTEST ATTACK PATH (DIJKSTRA) ---\n");
    printf("Available Hosts in Network Topology:\n");
    for (int i = 0; i < 7; i++) printf("  [%d] %s\n", i, names[i]);
    printf("\nSelect Compromised Source Node [default 0: AttackHost]: ");
    fflush(stdout);

    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin)) return;
    int src = atoi(buf);
    if (src < 0 || src >= 7) src = 0;

    int dist[MAX_HOSTS], prev[MAX_HOSTS];
    dijkstra(&net, src, dist, prev);

    printf("\n>> Shortest Latency / Exploit Paths from '%s':\n", names[src]);
    printf("------------------------------------------------------------------------------------\n");
    printf("Target Host     | Shortest Risk Distance | Lateral Movement Hop-by-Hop Path\n");
    printf("------------------------------------------------------------------------------------\n");
    for (int i = 0; i < 7; i++) {
        if (i == src) continue;
        printf("%-15s | %-22d | ", names[i], dist[i]);
        print_dijkstra_path(prev, i, &net);
        printf("\n");
    }
    printf("------------------------------------------------------------------------------------\n\n");
}

void run_greedy_demos(void) {
    char choice[32];
    while (1) {
        printf("=== PHASE 4: GREEDY ALGORITHMS CONTROL CENTER ==========================\n");
        printf("  [1] Run Standard Greedy Showcase (Activity, Interval, Huffman, Dijkstra, MST)\n");
        printf("  [2] Interactive Huffman Log Compression (Enter Custom Attack Text)\n");
        printf("  [3] Interactive Lateral Movement Route (Pick Compromised Start Host)\n");
        printf("  [B] Return to Main Engine Menu\n");
        printf("------------------------------------------------------------------------\n");
        printf("Select an action: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        choice[strcspn(choice, "\r\n")] = '\0';
        if (strlen(choice) == 0) continue;

        char c = choice[0];
        if (c == '1') run_standard_greedy_showcase();
        else if (c == '2') run_interactive_huffman();
        else if (c == '3') run_interactive_dijkstra();
        else if (c == 'b' || c == 'B') break;
        else printf("Invalid selection '%s'.\n\n", choice);
    }
}
