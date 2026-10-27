#include "algorithms/sorting.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ============================================================================
// QUICK SORT BY TIMESTAMP
// ============================================================================
void swapLogs(LogEntry* a, LogEntry* b) {
    LogEntry temp = *a;
    *a = *b;
    *b = temp;
}

int partition(LogEntry arr[], int low, int high) {
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
        quickSortByTimestamp(arr, low, pi - 1);
        quickSortByTimestamp(arr, pi + 1, high);
    }
}

// ============================================================================
// MERGE SORT BY SEVERITY (Stable Sort)
// ============================================================================
void mergeBySeverity(LogEntry arr[], int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;

    LogEntry* L = (LogEntry*)malloc(sizeof(LogEntry) * n1);
    LogEntry* R = (LogEntry*)malloc(sizeof(LogEntry) * n2);

    for (int i = 0; i < n1; i++) L[i] = arr[left + i];
    for (int j = 0; j < n2; j++) R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;

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

    while (i < n1) { arr[k] = L[i]; i++; k++; }
    while (j < n2) { arr[k] = R[j]; j++; k++; }

    free(L);
    free(R);
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
// INTERACTIVE DEMO RUNNER
// ============================================================================
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

static LogEntry g_liveLogs[50] = {
    {1728900500, "192.168.1.15", "10.0.0.8", 80,   "TCP", 3,  "Normal HTTP Traffic"},
    {1728900100, "192.168.1.50", "10.0.0.8", 443,  "TCP", 9,  "SQL Injection Attempt"},
    {1728900900, "10.0.0.5",     "192.168.1.100", 22, "TCP", 7,  "Failed SSH Brute Force"},
    {1728900300, "192.168.1.22", "10.0.0.8", 53,   "UDP", 2,  "Standard DNS Query"},
    {1728900700, "192.168.1.99", "10.0.0.2", 445,  "TCP", 10, "EternalBlue SMB Exploit"},
    {1728900200, "192.168.1.44", "10.0.0.8", 8080, "TCP", 5,  "Directory Traversal Probe"}
};
static int g_liveLogCount = 6;

static void run_standard_sorting(void) {
    displayLogs("Current Event Logs (Unsorted):", g_liveLogs, g_liveLogCount);

    LogEntry temp[50];
    memcpy(temp, g_liveLogs, sizeof(LogEntry) * g_liveLogCount);

    printf(">> Executing Quick Sort by Timestamp [O(n log n)]...\n");
    clock_t start = clock();
    quickSortByTimestamp(temp, 0, g_liveLogCount - 1);
    double qTime = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;
    displayLogs("Chronologically Ordered Event Logs (Quick Sort):", temp, g_liveLogCount);
    printf("   Execution Time: %.4f ms\n\n", qTime);

    printf(">> Executing Stable Merge Sort by Severity [Θ(n log n)]...\n");
    start = clock();
    mergeSortBySeverity(temp, 0, g_liveLogCount - 1);
    double mTime = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;
    displayLogs("Severity-Ranked Threat Triage (Merge Sort - Stable descending):", temp, g_liveLogCount);
    printf("   Execution Time: %.4f ms\n\n", mTime);
}

static void add_custom_log(void) {
    if (g_liveLogCount >= 45) {
        printf("Log buffer full.\n");
        return;
    }
    printf("\n--- ADD CUSTOM THREAT LOG TO LIVE ARRAY ---\n");
    LogEntry newLog;
    memset(&newLog, 0, sizeof(newLog));

    char buf[128];
    printf("Enter Source IP [e.g. 192.168.1.250]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\r\n")] = '\0';
    strncpy(newLog.source_ip, (strlen(buf) > 0) ? buf : "192.168.1.250", sizeof(newLog.source_ip) - 1);

    strcpy(newLog.dest_ip, "10.0.0.8");
    newLog.port = 443;
    strcpy(newLog.protocol, "TCP");

    printf("Enter Threat Severity (1 to 10) [e.g. 10]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\r\n")] = '\0';
    newLog.severity = (strlen(buf) > 0) ? atoi(buf) : 10;
    if (newLog.severity < 1) newLog.severity = 1;
    if (newLog.severity > 10) newLog.severity = 10;

    printf("Enter Payload / Threat Name [e.g. Zero-Day Exploit Attempt]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    buf[strcspn(buf, "\r\n")] = '\0';
    strncpy(newLog.payload, (strlen(buf) > 0) ? buf : "Zero-Day Exploit Attempt", sizeof(newLog.payload) - 1);

    // Random out-of-order timestamp between 1728900000 and 1728901000
    newLog.timestamp = 1728900000 + (rand() % 1000);

    g_liveLogs[g_liveLogCount++] = newLog;
    printf("\n[ADDED] New log inserted! Total live logs: %d\n\n", g_liveLogCount);

    run_standard_sorting();
}

static void run_scale_sorting_benchmark(void) {
    char buf[64];
    printf("\nEnter number of random logs to generate & sort [e.g. 500, 2000, 10000]: ");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return;
    int n = atoi(buf);
    if (n < 10) n = 1000;
    if (n > 50000) n = 50000;

    printf("\n>> Generating %d random out-of-order network logs in memory...\n", n);
    LogEntry* a1 = (LogEntry*)malloc(sizeof(LogEntry) * n);
    LogEntry* a2 = (LogEntry*)malloc(sizeof(LogEntry) * n);
    if (!a1 || !a2) {
        printf("Memory allocation failed.\n");
        return;
    }

    for (int i = 0; i < n; i++) {
        a1[i].timestamp = (uint64_t)rand();
        a1[i].severity = (rand() % 10) + 1;
        a1[i].port = 80;
        strcpy(a1[i].source_ip, "192.168.1.1");
        strcpy(a1[i].dest_ip, "10.0.0.8");
        strcpy(a1[i].protocol, "TCP");
        strcpy(a1[i].payload, "Benchmarking Log");
        a2[i] = a1[i];
    }

    printf(">> Benchmarking QuickSort vs MergeSort live on Apple Silicon CPU...\n");
    clock_t start = clock();
    quickSortByTimestamp(a1, 0, n - 1);
    double qTime = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;

    start = clock();
    mergeSortBySeverity(a2, 0, n - 1);
    double mTime = ((double)(clock() - start) / CLOCKS_PER_SEC) * 1000.0;

    printf("\n------------------------------------------------------------------------------------\n");
    printf("   LIVE SORTING WORKLOAD COMPARISON (N = %d logs)                                    \n", n);
    printf("------------------------------------------------------------------------------------\n");
    printf("  Quick Sort (by Timestamp):         %10.4f ms\n", qTime);
    printf("  Merge Sort (by Severity, Stable):  %10.4f ms\n", mTime);
    printf("  Performance Verdict:               %s\n",
           (mTime <= qTime) ? "MergeSort exhibited better cache predictability & strict O(n log n) bound." :
                              "QuickSort was faster due to in-place cache locality.");
    printf("------------------------------------------------------------------------------------\n\n");

    free(a1);
    free(a2);
}

void run_sorting_demos(void) {
    char choice[32];
    while (1) {
        printf("=== PHASE 2.1: SORTING MODULE CONTROL CENTER ===========================\n");
        printf("  [1] Sort Current Event Logs (QuickSort by Time & MergeSort by Severity)\n");
        printf("  [2] Add a Custom Log Live & Re-Sort (Watch Position Change Live!)\n");
        printf("  [3] Dynamic Scaling Stress Benchmark (Choose N = 500, 5000, 20000)\n");
        printf("  [B] Return to Main Engine Menu\n");
        printf("------------------------------------------------------------------------\n");
        printf("Select an action: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) break;
        choice[strcspn(choice, "\r\n")] = '\0';
        if (strlen(choice) == 0) continue;

        char c = choice[0];
        if (c == '1') {
            run_standard_sorting();
        } else if (c == '2') {
            add_custom_log();
        } else if (c == '3') {
            run_scale_sorting_benchmark();
        } else if (c == 'b' || c == 'B') {
            break;
        } else {
            printf("Invalid selection '%s'.\n\n", choice);
        }
    }
}
