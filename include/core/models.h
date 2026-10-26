#ifndef MODELS_H
#define MODELS_H

#include <stdint.h>

// ============================================================================
// SYSTEM CONSTANTS
// ============================================================================
#define MAX_HOSTS       20
#define MAX_EDGES      100
#define MAX_ITEMS       50
#define MAX_LOG_ENTRIES 100
#define MAX_TEXT_LEN   512
#define INF         999999

// ============================================================================
// CORE RECORD: Network Event Log
// ============================================================================
typedef struct {
    uint64_t timestamp;      // Epoch timestamp in seconds
    char source_ip[16];      // e.g., "192.168.1.100"
    char dest_ip[16];        // e.g., "10.0.0.8"
    uint16_t port;           // Network port
    char protocol[8];        // e.g., "TCP", "UDP"
    int severity;            // Threat level 1 to 10
    char payload[256];       // The attack signature or raw log data
} LogEntry;

// ============================================================================
// Threat Signature (Known Attack Pattern)
// ============================================================================
typedef struct {
    int id;
    char name[64];
    char pattern[128];       // Exact string or keyword pattern
    int severity;            // Base severity 1-10
    char category[32];       // e.g., "injection", "brute_force", "exfil"
} Signature;

// ============================================================================
// Network Host / Asset
// ============================================================================
typedef struct {
    char ip[16];
    char hostname[64];
    char os[32];
    int risk_score;          // 0-100
    int is_critical;         // 1 = critical asset, 0 = normal
} Host;

// ============================================================================
// Correlated Security Alert
// ============================================================================
typedef struct {
    int id;
    uint64_t timestamp;
    int signature_id;
    char source_ip[16];
    char dest_ip[16];
    int priority;            // 1 (highest) to 5 (lowest)
    char status[16];         // "new", "investigating", "resolved"
    char description[256];
} Alert;

// ============================================================================
// Graph Structures (Attack Graph, Network Topology)
// ============================================================================
typedef struct {
    int src;
    int dest;
    int weight;              // Risk score, latency, or cost
    int capacity;            // Link bandwidth capacity
} Edge;

typedef struct {
    int num_nodes;
    int num_edges;
    int adj[MAX_HOSTS][MAX_HOSTS];        // Adjacency/weight matrix
    int capacity[MAX_HOSTS][MAX_HOSTS];   // Capacity matrix (for flow)
    char node_names[MAX_HOSTS][32];       // Human-readable node labels
    Edge edges[MAX_EDGES];                // Edge list (for Kruskal)
} Graph;

// ============================================================================
// Scheduling / Interval Structures (for Greedy)
// ============================================================================
typedef struct {
    int id;
    int start;
    int finish;
    char description[64];
} Activity;

// ============================================================================
// Knapsack Item — Security Tool / Resource (for DP)
// ============================================================================
typedef struct {
    char name[64];
    int cost;                // Budget units
    int value;               // Effectiveness score
} KnapsackItem;

// ============================================================================
// Huffman Tree Node (for Greedy — Log Compression)
// ============================================================================
typedef struct HuffmanNode {
    char ch;
    int freq;
    struct HuffmanNode* left;
    struct HuffmanNode* right;
} HuffmanNode;

// ============================================================================
// BST Node (for Searching — IP/Timestamp Index)
// ============================================================================
typedef struct BSTNode {
    uint64_t key;
    int data_index;          // Index into log array
    struct BSTNode* left;
    struct BSTNode* right;
} BSTNode;

#endif
