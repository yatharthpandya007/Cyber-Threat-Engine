#ifndef SEARCHING_H
#define SEARCHING_H

#include "core/models.h"

// ============================================================================
// Iterative Binary Search by timestamp
// Complexity: O(log n)
// ============================================================================
int binarySearchByTimestamp(LogEntry arr[], int low, int high, uint64_t target);

// ============================================================================
// Recursive Binary Search by timestamp
// Complexity: O(log n), Recurrence: T(n) = T(n/2) + O(1)
// ============================================================================
int binarySearchRecursive(LogEntry arr[], int low, int high, uint64_t target);

// ============================================================================
// BST Index — Insert and Search by key (timestamp/IP hash)
// Complexity: O(log n) average, O(n) worst (unbalanced)
// ============================================================================
BSTNode* bstInsert(BSTNode* root, uint64_t key, int data_index);
BSTNode* bstSearch(BSTNode* root, uint64_t key);
void bstInorder(BSTNode* root);
void bstFree(BSTNode* root);

// Demo function
void run_searching_demos(void);
void run_standard_searching_showcase(void);

#endif
