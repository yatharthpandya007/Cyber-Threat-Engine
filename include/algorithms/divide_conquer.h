#ifndef DIVIDE_CONQUER_H
#define DIVIDE_CONQUER_H

#include <stdint.h>
#include "core/models.h"

// ============================================================================
// Maximum Subarray Result
// ============================================================================
typedef struct {
    int low;        // Start index of the maximum subarray
    int high;       // End index of the maximum subarray
    int64_t sum;    // Sum of elements in the maximum subarray
} SubarrayResult;

// ============================================================================
// 1. Maximum Subarray (Divide & Conquer)
//    Domain: DDoS Attack Window Detection — find peak traffic surge interval
//    Complexity: Θ(n log n)
// ============================================================================
SubarrayResult maxCrossingSubarray(int arr[], int low, int mid, int high);
SubarrayResult maxSubarray(int arr[], int low, int high);

// ============================================================================
// 2. Fast Powering — Exponentiation by Squaring
//    Domain: Modular exponentiation for cryptographic key computation
//    Complexity: O(log n)
// ============================================================================
long long fastPower(long long base, long long exp, long long mod);

// ============================================================================
// 3. Celebrity Problem (Divide & Conquer / Elimination)
//    Domain: Honeypot Host Discovery — find the host everyone connects TO
//            but that connects to nobody else
//    Complexity: O(n)
// ============================================================================
int findCelebrity(int knows[][MAX_HOSTS], int n);

// ============================================================================
// 4. Classical Matrix Multiplication
//    Domain: Attack graph reachability — compute A² to find 2-hop attack paths
//    Complexity: O(n³)
// ============================================================================
void classicalMatMul(int n, int A[][MAX_HOSTS], int B[][MAX_HOSTS], int C[][MAX_HOSTS]);

// ============================================================================
// 5. Strassen Matrix Multiplication (for 2^k × 2^k matrices)
//    Domain: Optimized reachability computation — benchmark vs classical
//    Complexity: O(n^2.807)
// ============================================================================
void strassenMultiply(int n, int A[][MAX_HOSTS], int B[][MAX_HOSTS], int C[][MAX_HOSTS]);

// Demo function
void run_divide_conquer_demos(void);
void run_standard_dc_showcase(void);

#endif
