#ifndef SORTING_H
#define SORTING_H

#include "core/models.h"

// ============================================================================
// Quick Sort — sort logs by timestamp
// Complexity: O(n log n) average, O(n²) worst case
// ============================================================================
void swapLogs(LogEntry* a, LogEntry* b);
void quickSortByTimestamp(LogEntry arr[], int low, int high);

// ============================================================================
// Merge Sort — stable sort logs by severity (for alert triage)
// Complexity: Θ(n log n) all cases
// Recurrence: T(n) = 2T(n/2) + Θ(n) → Θ(n log n)
// ============================================================================
void mergeBySeverity(LogEntry arr[], int left, int mid, int right);
void mergeSortBySeverity(LogEntry arr[], int left, int right);

// Demo function
void run_sorting_demos(void);

#endif
