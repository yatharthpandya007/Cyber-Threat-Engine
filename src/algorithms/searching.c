#include "algorithms/searching.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// ITERATIVE BINARY SEARCH BY TIMESTAMP
// ============================================================================
int binarySearchByTimestamp(LogEntry arr[], int low, int high, uint64_t target) {
    while (low <= high) {
        int mid = low + (high - low) / 2;
        if (arr[mid].timestamp == target) return mid;
        if (arr[mid].timestamp < target) low = mid + 1;
        else high = mid - 1;
    }
    return -1;
}

// ============================================================================
// RECURSIVE BINARY SEARCH BY TIMESTAMP
// ============================================================================
int binarySearchRecursive(LogEntry arr[], int low, int high, uint64_t target) {
    if (low > high) return -1;
    int mid = low + (high - low) / 2;
    if (arr[mid].timestamp == target) return mid;
    else if (arr[mid].timestamp < target) return binarySearchRecursive(arr, mid + 1, high, target);
    else return binarySearchRecursive(arr, low, mid - 1, target);
}

// ============================================================================
// BINARY SEARCH TREE — Timestamp/IP Index
// ============================================================================
BSTNode* bstInsert(BSTNode* root, uint64_t key, int data_index) {
    if (root == NULL) {
        BSTNode* node = (BSTNode*)malloc(sizeof(BSTNode));
        node->key = key;
        node->data_index = data_index;
        node->left = NULL;
        node->right = NULL;
        return node;
    }
    if (key < root->key) root->left = bstInsert(root->left, key, data_index);
    else if (key > root->key) root->right = bstInsert(root->right, key, data_index);
    return root;
}

BSTNode* bstSearch(BSTNode* root, uint64_t key) {
    if (root == NULL || root->key == key) return root;
    if (key < root->key) return bstSearch(root->left, key);
    return bstSearch(root->right, key);
}

void bstInorder(BSTNode* root) {
    if (root != NULL) {
        bstInorder(root->left);
        printf("  [BST Node] Timestamp Key: %llu -> Log Index: %d\n", (unsigned long long)root->key, root->data_index);
        bstInorder(root->right);
    }
}

void bstFree(BSTNode* root) {
    if (root != NULL) {
        bstFree(root->left);
        bstFree(root->right);
        free(root);
    }
}

// ============================================================================
// INTERACTIVE DEMO RUNNER
// ============================================================================
static LogEntry g_searchLogs[] = {
    {1728900100, "192.168.1.50", "10.0.0.8", 443,  "TCP", 9,  "SQL Injection Attempt"},
    {1728900200, "192.168.1.44", "10.0.0.8", 8080, "TCP", 5,  "Directory Traversal Probe"},
    {1728900300, "192.168.1.22", "10.0.0.8", 53,   "UDP", 2,  "Standard DNS Query"},
    {1728900500, "192.168.1.15", "10.0.0.8", 80,   "TCP", 3,  "Normal HTTP Traffic"},
    {1728900700, "192.168.1.99", "10.0.0.2", 445,  "TCP", 10, "EternalBlue SMB Exploit"},
    {1728900900, "10.0.0.5",     "192.168.1.100", 22, "TCP", 7,  "Failed SSH Brute Force"}
};
static int g_numSearchLogs = sizeof(g_searchLogs) / sizeof(g_searchLogs[0]);

static BSTNode* g_dynamicBST = NULL;

static void show_log_table(void) {
    printf("\nCurrently Indexed Sorted Event Logs in Memory:\n");
    printf("------------------------------------------------------------------------------------\n");
    printf("Index | Timestamp    | Source IP       | Sev | Payload\n");
    printf("------------------------------------------------------------------------------------\n");
    for (int i = 0; i < g_numSearchLogs; i++) {
        printf("  [%d] | %llu | %-15s | %-3d | %s\n",
               i, (unsigned long long)g_searchLogs[i].timestamp,
               g_searchLogs[i].source_ip, g_searchLogs[i].severity, g_searchLogs[i].payload);
    }
    printf("------------------------------------------------------------------------------------\n\n");
}

static void run_interactive_search(void) {
    show_log_table();

    char buf[64];
    printf("Enter target Unix Timestamp to search [e.g. 1728900700, or pick any key above]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\r\n")] = '\0';
    if (strlen(buf) == 0) strcpy(buf, "1728900700");
    uint64_t target = (uint64_t)strtoull(buf, NULL, 10);

    printf("\n>> Executing Iterative Binary Search [O(log n)] for target %llu...\n", (unsigned long long)target);
    clock_t start = clock();
    int idxIter = binarySearchByTimestamp(g_searchLogs, 0, g_numSearchLogs - 1, target);
    double tIter = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;

    printf(">> Executing Recursive Binary Search [O(log n)] for target %llu...\n", (unsigned long long)target);
    start = clock();
    int idxRec = binarySearchRecursive(g_searchLogs, 0, g_numSearchLogs - 1, target);
    double tRec = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;

    if (idxIter != -1) {
        printf("\n[SUCCESS: KEY FOUND IN LOG DATABASE]\n");
        printf("  Array Position:    Index #%d\n", idxIter);
        printf("  Threat Payload:    %s\n", g_searchLogs[idxIter].payload);
        printf("  Threat Severity:   %d / 10\n", g_searchLogs[idxIter].severity);
        printf("  Source Host:       %s -> %s\n", g_searchLogs[idxIter].source_ip, g_searchLogs[idxIter].dest_ip);
        printf("  Search Latency:    Iterative: %.4f ms | Recursive: %.4f ms\n\n", tIter, tRec);
    } else {
        printf("\n[NOT FOUND] Target timestamp %llu does not exist in the active index.\n", (unsigned long long)target);
        printf("Binary search verified absence in O(log n) comparisons.\n\n");
    }
}

static void run_interactive_bst(void) {
    if (g_dynamicBST == NULL) {
        for (int i = 0; i < g_numSearchLogs; i++) {
            g_dynamicBST = bstInsert(g_dynamicBST, g_searchLogs[i].timestamp, i);
        }
    }

    printf("\n=== LIVE DYNAMIC BINARY SEARCH TREE (BST) INDEX ===\n");
    printf("1. Current BST In-Order Traversal (sorted by key):\n");
    bstInorder(g_dynamicBST);
    printf("\n");

    char buf[64];
    printf("Enter a NEW custom timestamp key to insert into the BST [e.g. 1728900400]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\r\n")] = '\0';
    if (strlen(buf) > 0) {
        uint64_t newKey = (uint64_t)strtoull(buf, NULL, 10);
        g_dynamicBST = bstInsert(g_dynamicBST, newKey, 99);
        printf("[INSERTED] Key %llu added to BST index!\n\n", (unsigned long long)newKey);
        printf("Updated In-Order Traversal:\n");
        bstInorder(g_dynamicBST);
        printf("\n");
    }
}

void run_standard_searching_showcase(void) {
    printf("=== PHASE 2.2: SEARCHING & BST INDEXING SHOWCASE =======================\n");
    show_log_table();
    uint64_t target = 1728900700ULL;
    printf(">> Executing Automated Iterative Binary Search [O(log n)] for target %llu...\n", (unsigned long long)target);
    int idxIter = binarySearchByTimestamp(g_searchLogs, 0, g_numSearchLogs - 1, target);
    printf(">> Executing Automated Recursive Binary Search [O(log n)] for target %llu...\n", (unsigned long long)target);
    int idxRec = binarySearchRecursive(g_searchLogs, 0, g_numSearchLogs - 1, target);
    if (idxIter != -1) {
        printf("\n[SUCCESS: KEY FOUND IN LOG DATABASE]\n");
        printf("  Array Position:    Index #%d (Recursive: #%d)\n", idxIter, idxRec);
        printf("  Threat Payload:    %s\n", g_searchLogs[idxIter].payload);
        printf("  Threat Severity:   %d / 10\n", g_searchLogs[idxIter].severity);
        printf("  Source Host:       %s -> %s\n\n", g_searchLogs[idxIter].source_ip, g_searchLogs[idxIter].dest_ip);
    }
    printf(">> Demonstrating BST Index In-Order Traversal:\n");
    if (g_dynamicBST == NULL) {
        for (int i = 0; i < g_numSearchLogs; i++) {
            g_dynamicBST = bstInsert(g_dynamicBST, g_searchLogs[i].timestamp, i);
        }
    }
    bstInorder(g_dynamicBST);
    printf("\n>> BST Search for target timestamp %llu:\n", (unsigned long long)target);
    BSTNode* res = bstSearch(g_dynamicBST, target);
    if (res) {
        printf("  [BST MATCH FOUND] Key: %llu -> Data Index: %d\n", (unsigned long long)res->key, res->data_index);
    }
    printf("========================================================================\n\n");
}

void run_searching_demos(void) {
    char choice[32];
    while (1) {
        printf("=== PHASE 2.2: SEARCHING & INDEXING CONTROL CENTER =====================\n");
        printf("  [1] Live Interactive Timestamp Search (Iterative & Recursive)\n");
        printf("  [2] Live Dynamic Binary Search Tree (BST) Index (Insert & Traverse)\n");
        printf("  [B] Return to Main Engine Menu\n");
        printf("------------------------------------------------------------------------\n");
        printf("Select an action: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        choice[strcspn(choice, "\r\n")] = '\0';
        if (strlen(choice) == 0) continue;

        char c = choice[0];
        if (c == '1') {
            run_interactive_search();
        } else if (c == '2') {
            run_interactive_bst();
        } else if (c == 'b' || c == 'B') {
            break;
        } else {
            printf("Invalid selection '%s'.\n\n", choice);
        }
    }
}
