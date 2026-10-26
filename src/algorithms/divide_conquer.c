#include "algorithms/divide_conquer.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>

// ============================================================================
// 1. MAXIMUM SUBARRAY — Divide & Conquer (CLRS Chapter 4)
// ============================================================================
// Domain: Given traffic deltas per interval, find the contiguous window with
//         the largest total spike — the signature of a volumetric DDoS attack.
// Recurrence: T(n) = 2T(n/2) + Θ(n) → Θ(n log n) [Master Theorem Case 2]
// ============================================================================

SubarrayResult maxCrossingSubarray(int arr[], int low, int mid, int high) {
    int64_t left_sum = INT64_MIN;
    int64_t sum = 0;
    int max_left = mid;

    for (int i = mid; i >= low; i--) {
        sum += arr[i];
        if (sum > left_sum) {
            left_sum = sum;
            max_left = i;
        }
    }

    int64_t right_sum = INT64_MIN;
    sum = 0;
    int max_right = mid + 1;

    for (int j = mid + 1; j <= high; j++) {
        sum += arr[j];
        if (sum > right_sum) {
            right_sum = sum;
            max_right = j;
        }
    }

    SubarrayResult result;
    result.low = max_left;
    result.high = max_right;
    result.sum = left_sum + right_sum;
    return result;
}

SubarrayResult maxSubarray(int arr[], int low, int high) {
    if (low == high) {
        SubarrayResult base;
        base.low = low;
        base.high = high;
        base.sum = arr[low];
        return base;
    }

    int mid = low + (high - low) / 2;

    SubarrayResult left  = maxSubarray(arr, low, mid);
    SubarrayResult right = maxSubarray(arr, mid + 1, high);
    SubarrayResult cross = maxCrossingSubarray(arr, low, mid, high);

    if (left.sum >= right.sum && left.sum >= cross.sum) {
        return left;
    } else if (right.sum >= left.sum && right.sum >= cross.sum) {
        return right;
    } else {
        return cross;
    }
}

// ============================================================================
// 2. FAST POWERING — Exponentiation by Squaring
// ============================================================================
// Domain: Modular exponentiation for RSA-style crypto key computation.
//         Computes (base^exp) mod m efficiently.
// Recurrence: T(n) = T(n/2) + O(1) → O(log n) [Master Theorem Case 2]
// ============================================================================

long long fastPower(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;

    while (exp > 0) {
        // If exp is odd, multiply result with base
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        // exp must be even now
        exp = exp / 2;
        base = (base * base) % mod;
    }
    return result;
}

// ============================================================================
// 3. CELEBRITY PROBLEM — Elimination Algorithm
// ============================================================================
// Domain: Honeypot Discovery — in a network of n hosts, find the host that
//         every other host connects to, but that itself connects to nobody.
//         This is the network "honeypot" or "sinkhole" node.
// Complexity: O(n) — eliminate one candidate per comparison
// ============================================================================

int findCelebrity(int knows[][MAX_HOSTS], int n) {
    // Step 1: Find a candidate using elimination
    int candidate = 0;
    for (int i = 1; i < n; i++) {
        // If candidate knows i, candidate can't be celebrity
        if (knows[candidate][i]) {
            candidate = i;
        }
    }

    // Step 2: Verify the candidate
    for (int i = 0; i < n; i++) {
        if (i != candidate) {
            // Celebrity must not know anyone, and everyone must know celebrity
            if (knows[candidate][i] || !knows[i][candidate]) {
                return -1;  // No celebrity exists
            }
        }
    }
    return candidate;
}

// ============================================================================
// 4. CLASSICAL MATRIX MULTIPLICATION — O(n³)
// ============================================================================
// Domain: Attack-graph reachability. If A is the adjacency matrix, then A²[i][j]
//         gives the number of 2-hop paths from host i to host j.
// Complexity: O(n³)
// ============================================================================

void classicalMatMul(int n, int A[][MAX_HOSTS], int B[][MAX_HOSTS], int C[][MAX_HOSTS]) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            C[i][j] = 0;
            for (int k = 0; k < n; k++) {
                C[i][j] += A[i][k] * B[k][j];
            }
        }
    }
}

// ============================================================================
// 5. STRASSEN MATRIX MULTIPLICATION — O(n^2.807)
// ============================================================================
// Domain: Optimized reachability — asymptotically faster for large matrices.
//         For small n, we fall back to classical (Strassen overhead not worth it).
// Recurrence: T(n) = 7T(n/2) + Θ(n²) → O(n^log₂7) ≈ O(n^2.807)
//
// NOTE: This implementation works for n that is a power of 2.
//       For the demo, we pad matrices to the next power of 2 if needed.
// ============================================================================

// Helper: add two n×n submatrices
static void matAdd(int n, int A[][MAX_HOSTS], int B[][MAX_HOSTS], int C[][MAX_HOSTS],
                   int arS, int acS, int brS, int bcS, int crS, int ccS) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            C[crS + i][ccS + j] = A[arS + i][acS + j] + B[brS + i][bcS + j];
}

// Helper: subtract two n×n submatrices
static void matSub(int n, int A[][MAX_HOSTS], int B[][MAX_HOSTS], int C[][MAX_HOSTS],
                   int arS, int acS, int brS, int bcS, int crS, int ccS) {
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            C[crS + i][ccS + j] = A[arS + i][acS + j] - B[brS + i][bcS + j];
}

void strassenMultiply(int n, int A[][MAX_HOSTS], int B[][MAX_HOSTS], int C[][MAX_HOSTS]) {
    // Base case: for small matrices, use classical multiplication
    if (n <= 2) {
        classicalMatMul(n, A, B, C);
        return;
    }

    // For simplicity within the project scope, we use classical for all sizes
    // since our demo matrices are small (< 8). The Strassen recurrence
    // T(n) = 7T(n/2) + Θ(n²) → O(n^2.807) applies to large matrices.
    //
    // A full Strassen implementation with dynamic sub-matrix allocation
    // would be production code; here we demonstrate the concept and benchmark.
    int half = n / 2;

    // Temporary matrices for Strassen's 7 products
    int M1[MAX_HOSTS][MAX_HOSTS], M2[MAX_HOSTS][MAX_HOSTS];
    int M3[MAX_HOSTS][MAX_HOSTS], M4[MAX_HOSTS][MAX_HOSTS];
    int M5[MAX_HOSTS][MAX_HOSTS], M6[MAX_HOSTS][MAX_HOSTS];
    int M7[MAX_HOSTS][MAX_HOSTS];
    int T1[MAX_HOSTS][MAX_HOSTS], T2[MAX_HOSTS][MAX_HOSTS];

    memset(M1, 0, sizeof(M1)); memset(M2, 0, sizeof(M2));
    memset(M3, 0, sizeof(M3)); memset(M4, 0, sizeof(M4));
    memset(M5, 0, sizeof(M5)); memset(M6, 0, sizeof(M6));
    memset(M7, 0, sizeof(M7));
    memset(T1, 0, sizeof(T1)); memset(T2, 0, sizeof(T2));

    // M1 = (A11 + A22) * (B11 + B22)
    matAdd(half, A, A, T1, 0, 0, half, half, 0, 0);
    matAdd(half, B, B, T2, 0, 0, half, half, 0, 0);
    classicalMatMul(half, T1, T2, M1);

    // M2 = (A21 + A22) * B11
    matAdd(half, A, A, T1, half, 0, half, half, 0, 0);
    classicalMatMul(half, T1, B, M2);

    // M3 = A11 * (B12 - B22)
    matSub(half, B, B, T2, 0, half, half, half, 0, 0);
    classicalMatMul(half, A, T2, M3);

    // M4 = A22 * (B21 - B11)
    matSub(half, B, B, T2, half, 0, 0, 0, 0, 0);
    // Copy A22 to T1 starting at (0,0)
    for (int i = 0; i < half; i++)
        for (int j = 0; j < half; j++)
            T1[i][j] = A[half + i][half + j];
    classicalMatMul(half, T1, T2, M4);

    // M5 = (A11 + A12) * B22
    matAdd(half, A, A, T1, 0, 0, 0, half, 0, 0);
    // Copy B22 to T2 starting at (0,0)
    for (int i = 0; i < half; i++)
        for (int j = 0; j < half; j++)
            T2[i][j] = B[half + i][half + j];
    classicalMatMul(half, T1, T2, M5);

    // M6 = (A21 - A11) * (B11 + B12)
    matSub(half, A, A, T1, half, 0, 0, 0, 0, 0);
    matAdd(half, B, B, T2, 0, 0, 0, half, 0, 0);
    classicalMatMul(half, T1, T2, M6);

    // M7 = (A12 - A22) * (B21 + B22)
    matSub(half, A, A, T1, 0, half, half, half, 0, 0);
    matAdd(half, B, B, T2, half, 0, half, half, 0, 0);
    classicalMatMul(half, T1, T2, M7);

    // C11 = M1 + M4 - M5 + M7
    for (int i = 0; i < half; i++)
        for (int j = 0; j < half; j++)
            C[i][j] = M1[i][j] + M4[i][j] - M5[i][j] + M7[i][j];

    // C12 = M3 + M5
    for (int i = 0; i < half; i++)
        for (int j = 0; j < half; j++)
            C[i][j + half] = M3[i][j] + M5[i][j];

    // C21 = M2 + M4
    for (int i = 0; i < half; i++)
        for (int j = 0; j < half; j++)
            C[i + half][j] = M2[i][j] + M4[i][j];

    // C22 = M1 - M2 + M3 + M6
    for (int i = 0; i < half; i++)
        for (int j = 0; j < half; j++)
            C[i + half][j + half] = M1[i][j] - M2[i][j] + M3[i][j] + M6[i][j];
}

// ============================================================================
// DEMO FUNCTION
// ============================================================================

void run_divide_conquer_demos(void) {
    printf("=== PHASE 3: DIVIDE & CONQUER ==========================================\n\n");

    // --- 3.1 Maximum Subarray (DDoS Detection) ---
    printf("--- 3.1 Maximum Subarray (DDoS Attack Window Detection) ---\n");
    int trafficDeltas[] = { -2, 10, -5, 25, 40, -15, 30, -8, -3, -20, 5, -7 };
    int numIntervals = sizeof(trafficDeltas) / sizeof(trafficDeltas[0]);
    uint64_t baseTime = 1728900000;
    int intervalSec = 300;

    printf("Traffic deltas (pps change per 5-min interval):\n  ");
    for (int i = 0; i < numIntervals; i++) {
        char tStr[6];
        time_t t = (time_t)(baseTime + i * intervalSec);
        strftime(tStr, sizeof(tStr), "%H:%M", localtime(&t));
        printf("%s:%+3d  ", tStr, trafficDeltas[i]);
    }
    printf("\n");

    SubarrayResult attack = maxSubarray(trafficDeltas, 0, numIntervals - 1);
    char s1[32], s2[32];
    time_t t1 = (time_t)(baseTime + attack.low * intervalSec);
    time_t t2 = (time_t)(baseTime + attack.high * intervalSec);
    strftime(s1, sizeof(s1), "%H:%M:%S", localtime(&t1));
    strftime(s2, sizeof(s2), "%H:%M:%S", localtime(&t2));
    printf("[DDoS ALERT] Attack window: %s — %s (%d intervals, %d min)\n",
           s1, s2, attack.high - attack.low + 1, (attack.high - attack.low + 1) * 5);
    printf("  Total surge: %+lld pps → %s\n\n",
           (long long)attack.sum, attack.sum > 50 ? "CRITICAL" : "WARNING");

    // --- 3.2 Fast Powering (Crypto Key Computation) ---
    printf("--- 3.2 Fast Powering (Modular Exponentiation) ---\n");
    long long base_val = 7, exponent = 256, modulus = 1000000007;
    long long result = fastPower(base_val, exponent, modulus);
    printf("Computing: %lld^%lld mod %lld\n", base_val, exponent, modulus);
    printf("Result: %lld\n", result);
    printf("Domain: RSA key computation — O(log n) vs naive O(n)\n\n");

    // --- 3.3 Celebrity Problem (Honeypot Discovery) ---
    printf("--- 3.3 Celebrity Problem (Honeypot Host Discovery) ---\n");
    const char* hostNames[] = {"WebServer", "Database", "Honeypot", "Attacker", "Firewall"};
    int nHosts = 5;
    int knows[MAX_HOSTS][MAX_HOSTS] = {
        //  Web  DB   Honey Atk  FW
        {0, 0, 1, 0, 0},  // WebServer knows Honeypot
        {0, 0, 1, 0, 0},  // Database knows Honeypot
        {0, 0, 0, 0, 0},  // Honeypot knows nobody (celebrity!)
        {0, 0, 1, 0, 0},  // Attacker knows Honeypot
        {0, 0, 1, 0, 0},  // Firewall knows Honeypot
    };
    int celeb = findCelebrity(knows, nHosts);
    if (celeb != -1) {
        printf("Honeypot identified: Host %d (%s)\n", celeb, hostNames[celeb]);
        printf("  → All other hosts connect to it, it connects to nobody.\n");
        printf("  → This is the network sinkhole/honeypot node.\n\n");
    } else {
        printf("No honeypot host found in the network.\n\n");
    }

    // --- 3.4 & 3.5 Matrix Multiplication (Attack Graph Reachability) ---
    printf("--- 3.4 Classical vs Strassen Matrix Multiply (Reachability) ---\n");
    int matN = 4;
    printf("Network adjacency matrix A (4 hosts):\n");
    int A[MAX_HOSTS][MAX_HOSTS] = {
        {0, 1, 0, 0},
        {0, 0, 1, 1},
        {1, 0, 0, 0},
        {0, 0, 1, 0}
    };
    const char* matHosts[] = {"Gateway", "WebSrv", "AppSrv", "DB"};
    printf("       ");
    for (int i = 0; i < matN; i++) printf("%-8s", matHosts[i]);
    printf("\n");
    for (int i = 0; i < matN; i++) {
        printf("  %-6s", matHosts[i]);
        for (int j = 0; j < matN; j++) printf("%-8d", A[i][j]);
        printf("\n");
    }

    int C_classic[MAX_HOSTS][MAX_HOSTS] = {0};
    int C_strassen[MAX_HOSTS][MAX_HOSTS] = {0};

    clock_t start = clock();
    classicalMatMul(matN, A, A, C_classic);
    clock_t classicTime = clock() - start;

    start = clock();
    strassenMultiply(matN, A, A, C_strassen);
    clock_t strassenTime = clock() - start;

    printf("\nA² (2-hop reachability) — Classical O(n³):\n");
    printf("       ");
    for (int i = 0; i < matN; i++) printf("%-8s", matHosts[i]);
    printf("\n");
    for (int i = 0; i < matN; i++) {
        printf("  %-6s", matHosts[i]);
        for (int j = 0; j < matN; j++) printf("%-8d", C_classic[i][j]);
        printf("\n");
    }

    printf("\nA² (2-hop reachability) — Strassen O(n^2.807):\n");
    printf("       ");
    for (int i = 0; i < matN; i++) printf("%-8s", matHosts[i]);
    printf("\n");
    for (int i = 0; i < matN; i++) {
        printf("  %-6s", matHosts[i]);
        for (int j = 0; j < matN; j++) printf("%-8d", C_strassen[i][j]);
        printf("\n");
    }

    // Verify results match
    int match = 1;
    for (int i = 0; i < matN && match; i++)
        for (int j = 0; j < matN && match; j++)
            if (C_classic[i][j] != C_strassen[i][j]) match = 0;

    printf("\nResults match: %s\n", match ? "YES ✓" : "NO ✗");
    printf("Classical time: %ld ticks | Strassen time: %ld ticks\n", (long)classicTime, (long)strassenTime);
    printf("Note: Strassen advantage appears at n ≥ 64 (crossover point).\n\n");
}
