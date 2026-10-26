#include "algorithms/searching.h"
#include <stdio.h>
#include <stdlib.h>

// ============================================================================
// ITERATIVE BINARY SEARCH BY TIMESTAMP
// ============================================================================
// Domain: Fast lookup of a specific event by its Unix Epoch timestamp in a
//         pre-sorted log array.
// Complexity: O(log n)
// ============================================================================

int binarySearchByTimestamp(LogEntry arr[], int low, int high, uint64_t target) {
    while (low <= high) {
        int mid = low + (high - low) / 2;

        // Check if target is present at mid
        if (arr[mid].timestamp == target) {
            return mid;
        }

        // If target is greater, ignore left half
        if (arr[mid].timestamp < target) {
            low = mid + 1;
        }
        // If target is smaller, ignore right half
        else {
            high = mid - 1;
        }
    }
    // Target was not found
    return -1;
}

// ============================================================================
// RECURSIVE BINARY SEARCH BY TIMESTAMP
// ============================================================================
// Domain: Same purpose as iterative variant; provided for algorithmic comparison.
// Recurrence: T(n) = T(n/2) + O(1) → O(log n) by Master Theorem (Case 2)
// ============================================================================

int binarySearchRecursive(LogEntry arr[], int low, int high, uint64_t target) {
    if (low > high) {
        return -1;  // Base case: not found
    }

    int mid = low + (high - low) / 2;

    if (arr[mid].timestamp == target) {
        return mid;
    } else if (arr[mid].timestamp < target) {
        return binarySearchRecursive(arr, mid + 1, high, target);
    } else {
        return binarySearchRecursive(arr, low, mid - 1, target);
    }
}

// ============================================================================
// BINARY SEARCH TREE — Timestamp/IP Index
// ============================================================================
// Domain: Dynamic index structure for O(log n) average-case insertion and
//         lookup of logs by timestamp or hashed IP address.
// Complexity: O(log n) average for balanced trees, O(n) worst case
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

    if (key < root->key) {
        root->left = bstInsert(root->left, key, data_index);
    } else if (key > root->key) {
        root->right = bstInsert(root->right, key, data_index);
    }
    // Duplicate keys are ignored (first-come indexing)

    return root;
}

BSTNode* bstSearch(BSTNode* root, uint64_t key) {
    if (root == NULL || root->key == key) {
        return root;
    }

    if (key < root->key) {
        return bstSearch(root->left, key);
    }
    return bstSearch(root->right, key);
}

void bstInorder(BSTNode* root) {
    if (root != NULL) {
        bstInorder(root->left);
        printf("  Key: %llu → Log Index: %d\n", (unsigned long long)root->key, root->data_index);
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
// DEMO RUNNER: SEARCHING MODULE
// ============================================================================
#include <time.h>

void run_searching_demos(void) {
    printf("=== PHASE 2.2: SEARCHING & INDEXING MODULE =============================\n\n");

    LogEntry sortedLogs[] = {
        {1728900100, "192.168.1.50", "10.0.0.8", 443, "TCP", 9, "SQL Injection Attempt"},
        {1728900200, "192.168.1.44", "10.0.0.8", 8080, "TCP", 5, "Directory Traversal Probe"},
        {1728900300, "192.168.1.22", "10.0.0.8", 53, "UDP", 2, "Standard DNS Query"},
        {1728900500, "192.168.1.15", "10.0.0.8", 80, "TCP", 3, "Normal HTTP Traffic"},
        {1728900700, "192.168.1.99", "10.0.0.2", 445, "TCP", 10, "EternalBlue SMB Exploit"},
        {1728900900, "10.0.0.5", "192.168.1.100", 22, "TCP", 7, "Failed SSH Brute Force"}
    };
    int n = sizeof(sortedLogs) / sizeof(sortedLogs[0]);

    uint64_t target = 1728900700;
    char timeStr[32];
    time_t rawTarget = (time_t)target;
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&rawTarget));

    printf("Querying chronologically sorted log database for incident timestamp:\n  Target: %llu (%s)\n\n",
           (unsigned long long)target, timeStr);

    // 1. Iterative Binary Search
    printf("1. Iterative Binary Search [O(log n)]:\n");
    int idxIter = binarySearchByTimestamp(sortedLogs, 0, n - 1, target);
    if (idxIter != -1) {
        printf("   [FOUND at index %d] Threat: %s | Severity: %d | Source: %s\n\n",
               idxIter, sortedLogs[idxIter].payload, sortedLogs[idxIter].severity, sortedLogs[idxIter].source_ip);
    } else {
        printf("   [NOT FOUND]\n\n");
    }

    // 2. Recursive Binary Search
    printf("2. Recursive Binary Search [T(n) = T(n/2) + O(1) -> O(log n)]:\n");
    int idxRec = binarySearchRecursive(sortedLogs, 0, n - 1, target);
    if (idxRec != -1) {
        printf("   [FOUND at index %d] Threat: %s | Severity: %d | Dest: %s\n\n",
               idxRec, sortedLogs[idxRec].payload, sortedLogs[idxRec].severity, sortedLogs[idxRec].dest_ip);
    } else {
        printf("   [NOT FOUND]\n\n");
    }

    // 3. Binary Search Tree (BST) Index
    printf("3. Domain-Specific Index: Binary Search Tree (BST) Indexing [O(log n) avg]:\n");
    printf("   Building dynamic BST index on event timestamps...\n");
    BSTNode* root = NULL;
    for (int i = 0; i < n; i++) {
        root = bstInsert(root, sortedLogs[i].timestamp, i);
    }

    printf("   In-order traversal of indexed logs:\n");
    bstInorder(root);

    printf("   Querying BST for key %llu...\n", (unsigned long long)target);
    BSTNode* match = bstSearch(root, target);
    if (match) {
        printf("   [BST MATCH CONFIRMED] Key %llu maps to LogEntry #%d: '%s'\n",
               (unsigned long long)match->key, match->data_index, sortedLogs[match->data_index].payload);
    } else {
        printf("   [BST MISS]\n");
    }
    bstFree(root);
    printf("\n");
}

