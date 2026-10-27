#ifndef STRINGS_H
#define STRINGS_H

#include "core/models.h"

// ============================================================================
// STRING MATCHING AND NUMBER THEORY MODULE
// Cybersecurity Log Threat Detection Engine
//
// Provides pattern matching algorithms for scanning network log payloads
// against known attack signatures, plus number-theoretic primitives for
// distributed secret reconstruction.
// ============================================================================

// ============================================================================
// NUMBER THEORY — Distributed Secret Reconstruction
// ============================================================================

/*
 * extendedGCD — Extended Euclidean Algorithm
 *
 * Computes gcd(a, b) and finds Bezout coefficients x, y such that
 *     a*x + b*y = gcd(a, b)
 *
 * Domain mapping: Core primitive for modular inverse computation, used in
 * cryptographic key reconstruction across distributed security nodes.
 *
 * Time complexity: O(log(min(a, b)))
 */
long long extendedGCD(long long a, long long b, long long* x, long long* y);

/*
 * modInverse — Modular Multiplicative Inverse
 *
 * Returns the modular inverse of a modulo m, i.e. a value x such that
 *     (a * x) ≡ 1 (mod m)
 * Requires gcd(a, m) = 1. Returns -1 if inverse does not exist.
 *
 * Domain mapping: Used in CRT-based secret reconstruction to invert
 * partial modular contributions from each security node.
 *
 * Time complexity: O(log m)
 */
long long modInverse(long long a, long long m);

/*
 * chineseRemainderTheorem — Chinese Remainder Theorem (CRT)
 *
 * Given a system of simultaneous congruences:
 *     x ≡ remainders[0] (mod moduli[0])
 *     x ≡ remainders[1] (mod moduli[1])
 *     ...
 *     x ≡ remainders[n-1] (mod moduli[n-1])
 * where all moduli are pairwise coprime, returns the smallest non-negative
 * solution x.
 *
 * Domain mapping: Distributed Secret Reconstruction — reconstruct a
 * secret key from partial residues held by different security nodes
 * (Shamir-like fragment reassembly).
 *
 * Time complexity: O(n * log(max_modulus))
 */
long long chineseRemainderTheorem(int remainders[], int moduli[], int n);

// ============================================================================
// STRING MATCHING — Attack Signature Detection
// ============================================================================

/*
 * naiveStringMatch — Brute-Force String Matching
 *
 * Slides the pattern over the text one position at a time, checking for
 * a match at each position by comparing all pattern characters.
 *
 * Domain mapping: Baseline Payload Scanner — brute-force search for
 * attack signatures in raw log payloads. Simple reference implementation.
 *
 * Time complexity: O(n * m) worst case, where n = |text|, m = |pattern|
 */
int naiveStringMatch(const char* text, const char* pattern,
                     int matches[], int maxMatches);

/*
 * rabinKarp — Rabin-Karp Rolling-Hash String Matching
 *
 * Uses a rolling hash function to quickly skip non-matching positions.
 * On hash collision, performs character-by-character verification.
 *   Base d = 256 (full ASCII alphabet size)
 *   Prime q = 101 (modular hash to prevent overflow)
 *
 * Domain mapping: Rolling-Hash Signature Detection — efficiently detect
 * attack patterns in large log streams using probabilistic hash filtering.
 *
 * Time complexity: Expected O(n + m), worst case O(n * m)
 */
int rabinKarp(const char* text, const char* pattern,
              int matches[], int maxMatches);

/*
 * finiteAutomatonMatch — Finite-Automaton (DFA) String Matching
 *
 * Builds a deterministic finite automaton whose transition table δ
 * encodes the pattern, then processes the text in a single pass with
 * no backtracking.
 *
 * Domain mapping: State-Machine Pattern Scanner — build a DFA for
 * deterministic, real-time signature detection in streaming log data.
 *
 * Time complexity: O(m * |Σ|) preprocessing + O(n) matching
 *                  where |Σ| = 256 (ASCII alphabet)
 */
int finiteAutomatonMatch(const char* text, const char* pattern,
                         int matches[], int maxMatches);

/*
 * computeLPSArray — KMP Failure Function (Longest Proper Prefix-Suffix)
 *
 * Computes the LPS array for pattern P:
 *   lps[i] = length of the longest proper prefix of P[0..i] that is
 *            also a suffix of P[0..i]
 *
 * Domain mapping: Preprocessing step for the KMP scanner, enabling
 * zero-backtrack pattern matching.
 *
 * Time complexity: O(m)
 */
void computeLPSArray(const char* pattern, int m, int lps[]);

/*
 * kmpSearch — Knuth-Morris-Pratt String Matching
 *
 * Uses the LPS (failure function) array to avoid re-examining characters
 * in the text after a partial match fails.
 *
 * Domain mapping: Optimized Threat Signature Scanner — zero-backtrack
 * pattern matching for real-time detection in high-throughput log streams.
 *
 * Time complexity: O(n + m) guaranteed
 */
int kmpSearch(const char* text, const char* pattern,
              int matches[], int maxMatches);

// ============================================================================
// DEMO / DRIVER
// ============================================================================

/*
 * run_strings_demos — Demonstrate all string matching and number theory
 * algorithms with cybersecurity-themed test data and benchmarks.
 */
void run_strings_demos(void);
void run_standard_strings_showcase(void);

#endif
