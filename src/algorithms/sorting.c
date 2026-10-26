#include "algorithms/sorting.h"
#include <string.h>

// ============================================================================
// QUICK SORT BY TIMESTAMP
// ============================================================================
// Domain: Chronological ordering of out-of-order event logs for analysis.
// Complexity: O(n log n) average, O(n²) worst (mitigated by random pivots)
// ============================================================================

void swapLogs(LogEntry* a, LogEntry* b) {
    LogEntry temp = *a;
    *a = *b;
    *b = temp;
}

// Standard partition function for Quick Sort
int partition(LogEntry arr[], int low, int high) {
    // We use the timestamp of the last element as the pivot
    uint64_t pivot = arr[high].timestamp;
    int i = (low - 1);

    for (int j = low; j <= high - 1; j++) {
        if (arr[j].timestamp < pivot) {
            i++;
            swapLogs(&arr[i], &arr[j]);
        }
    }
    swapLogs(&arr[i + 1], &arr[high]);
    return (i + 1);
}

void quickSortByTimestamp(LogEntry arr[], int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        // Recursively sort the left and right sides of the pivot
        quickSortByTimestamp(arr, low, pi - 1);
        quickSortByTimestamp(arr, pi + 1, high);
    }
}

// ============================================================================
// MERGE SORT BY SEVERITY (Stable Sort)
// ============================================================================
// Domain: Alert triage — rank events by severity while preserving chronological
//         order among events of equal severity (stability matters here).
// Recurrence: T(n) = 2T(n/2) + Θ(n)
// Solution:   Θ(n log n) by the Master Theorem (Case 2)
// ============================================================================

void mergeBySeverity(LogEntry arr[], int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;

    // Temporary arrays (stack-allocated for small n, heap for production)
    LogEntry L[n1], R[n2];

    for (int i = 0; i < n1; i++)
        L[i] = arr[left + i];
    for (int j = 0; j < n2; j++)
        R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;

    // Merge in descending severity order (highest severity first)
    while (i < n1 && j < n2) {
        if (L[i].severity >= R[j].severity) {
            arr[k] = L[i];
            i++;
        } else {
            arr[k] = R[j];
            j++;
        }
        k++;
    }

    // Copy remaining elements
    while (i < n1) {
        arr[k] = L[i];
        i++;
        k++;
    }
    while (j < n2) {
        arr[k] = R[j];
        j++;
        k++;
    }
}

void mergeSortBySeverity(LogEntry arr[], int left, int right) {
    if (left < right) {
        int mid = left + (right - left) / 2;
        mergeSortBySeverity(arr, left, mid);
        mergeSortBySeverity(arr, mid + 1, right);
        mergeBySeverity(arr, left, mid, right);
    }
}

// ============================================================================
// DEMO RUNNER: SORTING MODULE
// ============================================================================
#include <stdio.h>
#include <time.h>

static void displayLogs(const char* title, LogEntry logs[], int size) {
    printf("%s\n", title);
    printf("------------------------------------------------------------------------------------\n");
    printf("%-20s | %-15s | %-15s | %-4s | %-4s | %-3s | %s\n",
           "Timestamp", "Source IP", "Dest IP", "Port", "Prot", "Sev", "Payload / Signature");
    printf("------------------------------------------------------------------------------------\n");
    char timeStr[32];
    for (int i = 0; i < size; i++) {
        time_t rawtime = (time_t)logs[i].timestamp;
        struct tm * timeinfo = localtime(&rawtime);
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
        printf("%-20s | %-15s | %-15s | %-4u | %-4s | %-3d | %s\n",
               timeStr, logs[i].source_ip, logs[i].dest_ip,
               logs[i].port, logs[i].protocol, logs[i].severity, logs[i].payload);
    }
    printf("------------------------------------------------------------------------------------\n\n");
}

void run_sorting_demos(void) {
    printf("=== PHASE 2.1: SORTING MODULE ==========================================\n\n");

    LogEntry sampleLogs[] = {
        {1728900500, "192.168.1.15", "10.0.0.8", 80,   "TCP", 3,  "Normal HTTP Traffic"},
        {1728900100, "192.168.1.50", "10.0.0.8", 443,  "TCP", 9,  "SQL Injection Attempt"},
        {1728900900, "10.0.0.5",     "192.168.1.100", 22, "TCP", 7,  "Failed SSH Brute Force"},
        {1728900300, "192.168.1.22", "10.0.0.8", 53,   "UDP", 2,  "Standard DNS Query"},
        {1728900700, "192.168.1.99", "10.0.0.2", 445,  "TCP", 10, "EternalBlue SMB Exploit"},
        {1728900200, "192.168.1.44", "10.0.0.8", 8080, "TCP", 5,  "Directory Traversal Probe"}
    };
    int n = sizeof(sampleLogs) / sizeof(sampleLogs[0]);

    displayLogs("Initial Raw Ingested Event Logs (Unsorted):", sampleLogs, n);

    // 1. QuickSort by Timestamp
    printf(">> Executing Quick Sort by Timestamp [O(n log n)] for chronological timeline...\n");
    quickSortByTimestamp(sampleLogs, 0, n - 1);
    displayLogs("Chronologically Ordered Event Logs (Quick Sort):", sampleLogs, n);

    // 2. MergeSort by Severity
    printf(">> Executing Stable Merge Sort by Severity [Θ(n log n)] for alert triage...\n");
    mergeSortBySeverity(sampleLogs, 0, n - 1);
    displayLogs("Severity-Ranked Threat Triage (Merge Sort - Stable descending):", sampleLogs, n);
}

