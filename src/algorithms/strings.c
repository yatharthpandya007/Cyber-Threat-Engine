// ============================================================================
// STRING MATCHING AND NUMBER THEORY MODULE
// Cybersecurity Log Threat Detection Engine
//
// Implements pattern matching algorithms for scanning network log payloads
// against known attack signatures, plus number-theoretic primitives for
// distributed secret reconstruction (CRT).
// ============================================================================

#include "algorithms/strings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

// ============================================================================
// NUMBER THEORY HELPERS
// ============================================================================

/*
 * extendedGCD — Extended Euclidean Algorithm (CLRS §31.2)
 *
 * Computes gcd(a, b) and Bezout coefficients x, y such that
 *     a*x + b*y = gcd(a, b)
 *
 * Uses the recursive formulation:
 *     gcd(a, 0) = a, x = 1, y = 0
 *     gcd(a, b) = gcd(b, a mod b)
 *     then back-substitute to find x, y.
 *
 * Domain mapping: Core primitive for modular inverse computation,
 * used in cryptographic key reconstruction across distributed
 * security nodes.
 *
 * Time complexity: O(log(min(a, b)))
 */
long long extendedGCD(long long a, long long b, long long* x, long long* y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    long long x1, y1;
    long long g = extendedGCD(b, a % b, &x1, &y1);

    /* Back-substitution:
     *   gcd(a, b) = gcd(b, a % b)
     *   b*x1 + (a % b)*y1 = g
     *   b*x1 + (a - (a/b)*b)*y1 = g
     *   a*y1 + b*(x1 - (a/b)*y1) = g
     * So: x = y1, y = x1 - (a/b)*y1
     */
    *x = y1;
    *y = x1 - (a / b) * y1;

    return g;
}

/*
 * modInverse — Modular Multiplicative Inverse using Extended GCD
 *
 * Returns x such that (a * x) ≡ 1 (mod m).
 * Requires gcd(a, m) = 1. Returns -1 if the inverse does not exist.
 *
 * Domain mapping: Used in CRT-based secret reconstruction to invert
 * partial modular contributions from each security node.
 *
 * Time complexity: O(log m)
 */
long long modInverse(long long a, long long m) {
    long long x, y;
    long long g = extendedGCD(a, m, &x, &y);

    if (g != 1) {
        /* Inverse does not exist — a and m are not coprime */
        return -1;
    }

    /* Normalize to [0, m) */
    return ((x % m) + m) % m;
}

/*
 * chineseRemainderTheorem — CRT (CLRS §31.5 / standard construction)
 *
 * Given pairwise coprime moduli m_0, m_1, ..., m_{n-1} and corresponding
 * remainders r_0, r_1, ..., r_{n-1}, finds the unique x in [0, M) where
 * M = m_0 * m_1 * ... * m_{n-1} such that:
 *     x ≡ r_i (mod m_i)   for all i
 *
 * Construction:
 *     M  = product of all moduli
 *     M_i = M / m_i
 *     y_i = modInverse(M_i, m_i)
 *     x   = Σ (r_i * M_i * y_i) mod M
 *
 * Domain mapping: Distributed Secret Reconstruction — reconstruct a
 * secret key from partial residues held by different security nodes.
 *
 * Time complexity: O(n * log(max_modulus))
 */
long long chineseRemainderTheorem(int remainders[], int moduli[], int n) {
    /* Compute product M of all moduli */
    long long M = 1;
    for (int i = 0; i < n; i++) {
        M *= (long long)moduli[i];
    }

    long long x = 0;
    for (int i = 0; i < n; i++) {
        long long Mi = M / (long long)moduli[i];
        long long yi = modInverse(Mi, (long long)moduli[i]);

        x = (x + (long long)remainders[i] * Mi % M * yi % M) % M;
    }

    /* Normalize to non-negative */
    return ((x % M) + M) % M;
}

// ============================================================================
// STRING MATCHING ALGORITHMS
// ============================================================================

/*
 * naiveStringMatch — Brute-Force Pattern Matching (CLRS §32.1)
 *
 * For each valid shift s in [0, n-m], checks whether
 *     text[s..s+m-1] == pattern[0..m-1]
 * by comparing character-by-character.
 *
 * Domain mapping: Baseline Payload Scanner — brute-force search for
 * attack signatures in raw log payloads.
 *
 * Time complexity: O(n * m) worst case
 */
int naiveStringMatch(const char* text, const char* pattern,
                     int matches[], int maxMatches) {
    int n = (int)strlen(text);
    int m = (int)strlen(pattern);
    int count = 0;

    if (m == 0 || m > n) return 0;

    for (int s = 0; s <= n - m; s++) {
        int j;
        for (j = 0; j < m; j++) {
            if (text[s + j] != pattern[j]) {
                break;
            }
        }
        if (j == m) {
            /* Full match found at shift s */
            if (count < maxMatches) {
                matches[count] = s;
            }
            count++;
        }
    }

    return count;
}

/*
 * rabinKarp — Rabin-Karp Rolling-Hash Pattern Matching (CLRS §32.2)
 *
 * Computes a rolling hash over the text window and compares it against
 * the pattern hash. On collision, verifies character-by-character.
 *
 *   Hash function: h(s) = ( Σ s[i] * d^(m-1-i) ) mod q
 *   Rolling update: h(s+1) = (d * (h(s) - text[s]*h_coeff) + text[s+m]) mod q
 *   where h_coeff = d^(m-1) mod q
 *
 * Parameters:
 *   d = 256 (number of characters in the input alphabet)
 *   q = 101 (a prime for modular hashing)
 *
 * Domain mapping: Rolling-Hash Signature Detection — efficiently detect
 * attack patterns in large log streams with probabilistic filtering.
 *
 * Time complexity: Expected O(n + m), worst case O(n * m)
 */
int rabinKarp(const char* text, const char* pattern,
              int matches[], int maxMatches) {
    const int d = 256;  /* Alphabet size */
    const int q = 101;  /* A prime modulus */

    int n = (int)strlen(text);
    int m = (int)strlen(pattern);
    int count = 0;

    if (m == 0 || m > n) return 0;

    /* Compute h = d^(m-1) mod q — the high-order digit coefficient */
    int h = 1;
    for (int i = 0; i < m - 1; i++) {
        h = (h * d) % q;
    }

    /* Compute initial hash values for pattern and first text window */
    int p_hash = 0;  /* Hash of pattern */
    int t_hash = 0;  /* Hash of current text window */
    for (int i = 0; i < m; i++) {
        p_hash = (d * p_hash + (unsigned char)pattern[i]) % q;
        t_hash = (d * t_hash + (unsigned char)text[i]) % q;
    }

    /* Slide the pattern over the text */
    for (int s = 0; s <= n - m; s++) {
        if (p_hash == t_hash) {
            /* Hash match — verify character by character */
            int j;
            for (j = 0; j < m; j++) {
                if (text[s + j] != pattern[j]) {
                    break;
                }
            }
            if (j == m) {
                if (count < maxMatches) {
                    matches[count] = s;
                }
                count++;
            }
        }

        /* Compute hash for next window: remove leading char, add trailing */
        if (s < n - m) {
            t_hash = (d * (t_hash - (unsigned char)text[s] * h) +
                       (unsigned char)text[s + m]) % q;

            /* Ensure non-negative */
            if (t_hash < 0) {
                t_hash += q;
            }
        }
    }

    return count;
}

/*
 * finiteAutomatonMatch — DFA-Based Pattern Matching (CLRS §32.3)
 *
 * Preprocessing: Build transition table δ[state][char] for all states
 * 0..m and all characters 0..255. For state q and character c,
 * δ(q, c) = the length of the longest proper suffix of P[0..q-1]c
 * that is also a prefix of P.
 *
 * Matching: Process each character of text through the DFA in one pass.
 * When we reach the accepting state (state == m), we have a match.
 *
 * Domain mapping: State-Machine Pattern Scanner — build a DFA for
 * deterministic, real-time signature detection in streaming log data.
 *
 * Time complexity: O(m * |Σ|) preprocessing + O(n) matching
 */
int finiteAutomatonMatch(const char* text, const char* pattern,
                         int matches[], int maxMatches) {
    int n = (int)strlen(text);
    int m = (int)strlen(pattern);
    int count = 0;

    if (m == 0 || m > n) return 0;

    /*
     * Allocate transition table δ[state][char]
     * Dimensions: (m+1) states × 256 characters
     * We use dynamic allocation to handle arbitrary pattern lengths
     * within MAX_TEXT_LEN.
     */
    int (*delta)[256] = malloc((size_t)(m + 1) * 256 * sizeof(int));
    if (!delta) {
        fprintf(stderr, "[FATAL] Memory allocation failed for DFA table\n");
        return 0;
    }

    /*
     * Build the transition function using suffix-checking method.
     * For each state q (0..m) and each character c (0..255):
     *   Let k = min(m, q+1)
     *   Find largest k such that P[0..k-1] is a suffix of P[0..q-1]c
     *   δ(q, c) = k
     */
    for (int q = 0; q <= m; q++) {
        for (int c = 0; c < 256; c++) {
            /* Try k from min(m, q+1) down to 0 */
            int k = (q + 1 <= m) ? q + 1 : m;

            while (k > 0) {
                /* Check if P[0..k-1] is a suffix of P[0..q-1] + c */
                /* The last character must match: P[k-1] == c */
                if ((unsigned char)pattern[k - 1] == c) {
                    /* Check if P[0..k-2] matches the suffix of P[0..q-1]
                     * i.e., P[j] == P[q - (k-1) + j] for j = 0..k-2 */
                    int match = 1;
                    for (int j = 0; j < k - 1; j++) {
                        int text_idx = q - (k - 1) + j;
                        if (text_idx < 0 ||
                            (unsigned char)pattern[j] !=
                            (unsigned char)pattern[text_idx]) {
                            match = 0;
                            break;
                        }
                    }
                    if (match) break;
                }
                k--;
            }

            delta[q][c] = k;
        }
    }

    /* Run the DFA on the text — single linear scan */
    int state = 0;
    for (int i = 0; i < n; i++) {
        state = delta[state][(unsigned char)text[i]];
        if (state == m) {
            /* Match found; the match starts at position i - m + 1 */
            if (count < maxMatches) {
                matches[count] = i - m + 1;
            }
            count++;
        }
    }

    free(delta);
    return count;
}

/*
 * computeLPSArray — KMP Failure Function (CLRS §32.4)
 *
 * Computes the Longest Proper Prefix-Suffix (LPS) array for the pattern.
 *   lps[i] = length of the longest proper prefix of P[0..i]
 *            that is also a suffix of P[0..i]
 *
 * This array allows the KMP matcher to skip redundant comparisons
 * by "falling back" to the longest known prefix match.
 *
 * Domain mapping: Preprocessing step for zero-backtrack threat scanning.
 *
 * Time complexity: O(m)
 */
void computeLPSArray(const char* pattern, int m, int lps[]) {
    lps[0] = 0;  /* LPS of single character is always 0 */

    int len = 0;  /* Length of the previous longest prefix-suffix */
    int i = 1;

    while (i < m) {
        if (pattern[i] == pattern[len]) {
            len++;
            lps[i] = len;
            i++;
        } else {
            if (len != 0) {
                /* Fall back using the LPS array (do NOT increment i) */
                len = lps[len - 1];
            } else {
                lps[i] = 0;
                i++;
            }
        }
    }
}

/*
 * kmpSearch — Knuth-Morris-Pratt Pattern Matching (CLRS §32.4)
 *
 * Uses the LPS (failure function) array to avoid re-examining text
 * characters after a partial match failure. The text pointer never
 * backs up.
 *
 * Domain mapping: Optimized Threat Signature Scanner — zero-backtrack
 * pattern matching for real-time detection in high-throughput log streams.
 *
 * Time complexity: O(n + m) guaranteed
 */
int kmpSearch(const char* text, const char* pattern,
              int matches[], int maxMatches) {
    int n = (int)strlen(text);
    int m = (int)strlen(pattern);
    int count = 0;

    if (m == 0 || m > n) return 0;

    /* Compute the LPS (failure function) array */
    int* lps = malloc((size_t)m * sizeof(int));
    if (!lps) {
        fprintf(stderr, "[FATAL] Memory allocation failed for LPS array\n");
        return 0;
    }
    computeLPSArray(pattern, m, lps);

    int i = 0;  /* Index into text */
    int j = 0;  /* Index into pattern */

    while (i < n) {
        if (text[i] == pattern[j]) {
            i++;
            j++;
        }

        if (j == m) {
            /* Full match found at position i - j */
            if (count < maxMatches) {
                matches[count] = i - j;
            }
            count++;
            /* Use LPS to skip ahead */
            j = lps[j - 1];
        } else if (i < n && text[i] != pattern[j]) {
            if (j != 0) {
                /* Fall back using LPS — no text backtrack */
                j = lps[j - 1];
            } else {
                i++;
            }
        }
    }

    free(lps);
    return count;
}

// ============================================================================
// DEMO / DRIVER
// ============================================================================

/*
 * Helper: print a horizontal rule for visual separation.
 */
static void print_separator(void) {
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

/*
 * Helper: print match positions.
 */
static void print_matches(const char* algo_name, int matches[], int count) {
    printf("  %-28s : ", algo_name);
    if (count == 0) {
        printf("(no matches)\n");
    } else {
        printf("Found %d match(es) at position(s): ", count);
        for (int i = 0; i < count; i++) {
            printf("%d", matches[i]);
            if (i < count - 1) printf(", ");
        }
        printf("\n");
    }
}

/*
 * Helper: check if all four algorithms agree on their results.
 */
static bool results_agree(int m1[], int c1, int m2[], int c2,
                           int m3[], int c3, int m4[], int c4) {
    if (c1 != c2 || c1 != c3 || c1 != c4) return false;
    for (int i = 0; i < c1; i++) {
        if (m1[i] != m2[i] || m1[i] != m3[i] || m1[i] != m4[i])
            return false;
    }
    return true;
}

/*
 * run_strings_demos — Demonstrate all string matching and number theory
 * algorithms with cybersecurity-themed test data, clear output, and a
 * performance benchmark comparison.
 */
void run_strings_demos(void) {
    printf("\n");
    print_separator();
    printf("  🔐 STRING MATCHING & NUMBER THEORY MODULE — CYBER THREAT ENGINE\n");
    print_separator();

    // ========================================================================
    // SECTION 1: Chinese Remainder Theorem — Distributed Secret Reconstruction
    // ========================================================================
    printf("\n");
    print_separator();
    printf("  §1  CHINESE REMAINDER THEOREM — Distributed Secret Reconstruction\n");
    print_separator();
    printf("\n");
    printf("  Scenario: A cryptographic key was split using modular residues\n");
    printf("  and distributed across 3 security nodes. After a breach, we\n");
    printf("  recovered the fragments and must reconstruct the original key.\n");
    printf("\n");
    printf("  Recovered fragments:\n");

    int remainders[] = {2, 3, 2};
    int moduli[]     = {3, 5, 7};
    int n_crt = 3;

    for (int i = 0; i < n_crt; i++) {
        printf("    Node %d:  x ≡ %d (mod %d)\n", i + 1, remainders[i], moduli[i]);
    }

    printf("\n  Computing extended GCD intermediates:\n");
    for (int i = 0; i < n_crt; i++) {
        long long M_total = 1;
        for (int j = 0; j < n_crt; j++) M_total *= moduli[j];
        long long Mi = M_total / moduli[i];
        long long inv = modInverse(Mi, moduli[i]);
        printf("    M_%d = %lld,  M_%d^(-1) mod %d = %lld\n",
               i, Mi, i, moduli[i], inv);
    }

    long long secret = chineseRemainderTheorem(remainders, moduli, n_crt);
    printf("\n  ✅ Reconstructed secret key: x = %lld\n", secret);
    printf("  Verification:\n");
    for (int i = 0; i < n_crt; i++) {
        printf("    %lld mod %d = %lld  (expected %d) %s\n",
               secret, moduli[i], secret % moduli[i], remainders[i],
               (secret % moduli[i] == remainders[i]) ? "✓" : "✗ MISMATCH");
    }

    /* Additional CRT example */
    printf("\n  --- Additional reconstruction scenario ---\n");
    int remainders2[] = {1, 4, 6};
    int moduli2[]     = {5, 7, 11};
    printf("  Fragments: x ≡ 1 (mod 5), x ≡ 4 (mod 7), x ≡ 6 (mod 11)\n");
    long long secret2 = chineseRemainderTheorem(remainders2, moduli2, 3);
    printf("  ✅ Reconstructed secret key: x = %lld\n", secret2);
    for (int i = 0; i < 3; i++) {
        printf("    %lld mod %d = %lld  (expected %d) %s\n",
               secret2, moduli2[i], secret2 % moduli2[i], remainders2[i],
               (secret2 % moduli2[i] == remainders2[i]) ? "✓" : "✗ MISMATCH");
    }

    // ========================================================================
    // SECTION 2: String Matching — Attack Signature Scanning
    // ========================================================================
    printf("\n");
    print_separator();
    printf("  §2  STRING MATCHING — Attack Signature Scanning\n");
    print_separator();
    printf("\n");

    /* Simulated raw network log payload */
    const char* log_payload =
        "GET /admin/login HTTP/1.1 Host: 10.0.0.8 "
        "User-Agent: Mozilla/5.0 Cookie: session=abc123 "
        "POST /api/data HTTP/1.1 Content: DROP TABLE users; "
        "SELECT * FROM credentials WHERE 1=1; "
        "UNION SELECT password FROM admin_users; "
        "GET /admin/dashboard HTTP/1.1 Authorization: Bearer tok_admin_xyz";

    printf("  Simulated log payload (%d chars):\n", (int)strlen(log_payload));
    printf("  ┌─────────────────────────────────────────────────────────────┐\n");

    /* Print the payload in wrapped lines */
    int payload_len = (int)strlen(log_payload);
    int line_width = 59;
    for (int pos = 0; pos < payload_len; pos += line_width) {
        printf("  │ ");
        int remaining = payload_len - pos;
        int to_print = (remaining < line_width) ? remaining : line_width;
        for (int k = 0; k < to_print; k++) {
            putchar(log_payload[pos + k]);
        }
        /* Pad the rest */
        for (int k = to_print; k < line_width; k++) {
            putchar(' ');
        }
        printf(" │\n");
    }
    printf("  └─────────────────────────────────────────────────────────────┘\n");

    /* Attack signatures to scan for */
    const char* signatures[] = {
        "DROP TABLE",
        "UNION SELECT",
        "admin"
    };
    const char* sig_categories[] = {
        "SQL Injection (data destruction)",
        "SQL Injection (data exfiltration)",
        "Privilege Escalation / Recon"
    };
    int num_sigs = 3;

    #define MAX_MATCH 64

    for (int s = 0; s < num_sigs; s++) {
        printf("\n  ── Scanning for signature: \"%s\" ──\n", signatures[s]);
        printf("  Category: %s\n\n", sig_categories[s]);

        int m_naive[MAX_MATCH], m_rk[MAX_MATCH],
            m_dfa[MAX_MATCH], m_kmp[MAX_MATCH];

        int c_naive = naiveStringMatch(log_payload, signatures[s],
                                       m_naive, MAX_MATCH);
        int c_rk    = rabinKarp(log_payload, signatures[s],
                                m_rk, MAX_MATCH);
        int c_dfa   = finiteAutomatonMatch(log_payload, signatures[s],
                                           m_dfa, MAX_MATCH);
        int c_kmp   = kmpSearch(log_payload, signatures[s],
                                m_kmp, MAX_MATCH);

        print_matches("Naive (Brute-Force)",  m_naive, c_naive);
        print_matches("Rabin-Karp (Rolling Hash)", m_rk, c_rk);
        print_matches("Finite Automaton (DFA)",    m_dfa, c_dfa);
        print_matches("KMP (Zero-Backtrack)",      m_kmp, c_kmp);

        if (results_agree(m_naive, c_naive, m_rk, c_rk,
                          m_dfa, c_dfa, m_kmp, c_kmp)) {
            printf("  ✅ All four algorithms AGREE on the results.\n");
        } else {
            printf("  ⚠️  WARNING: Algorithm results DISAGREE!\n");
        }

        /* Show context around each match */
        if (c_naive > 0) {
            printf("  Context:\n");
            for (int i = 0; i < c_naive && i < MAX_MATCH; i++) {
                int start = m_naive[i] - 10;
                if (start < 0) start = 0;
                int end = m_naive[i] + (int)strlen(signatures[s]) + 10;
                if (end > payload_len) end = payload_len;

                printf("    pos %3d: \"...%.*s...\"\n",
                       m_naive[i], end - start, log_payload + start);
            }
        }
    }

    // ========================================================================
    // SECTION 3: Performance Benchmark — Algorithm Comparison
    // ========================================================================
    printf("\n");
    print_separator();
    printf("  §3  PERFORMANCE BENCHMARK — Algorithm Speed Comparison\n");
    print_separator();
    printf("\n");

    const int BENCH_ITERATIONS = 10000;
    const char* bench_pattern = "UNION SELECT";

    printf("  Benchmark: %d iterations, pattern = \"%s\"\n",
           BENCH_ITERATIONS, bench_pattern);
    printf("  Text length: %d characters\n\n", payload_len);

    int bench_matches[MAX_MATCH];
    clock_t start, end;
    double t_naive, t_rk, t_dfa, t_kmp;

    /* Benchmark Naive */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        naiveStringMatch(log_payload, bench_pattern,
                         bench_matches, MAX_MATCH);
    }
    end = clock();
    t_naive = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    /* Benchmark Rabin-Karp */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        rabinKarp(log_payload, bench_pattern,
                  bench_matches, MAX_MATCH);
    }
    end = clock();
    t_rk = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    /* Benchmark Finite Automaton */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        finiteAutomatonMatch(log_payload, bench_pattern,
                             bench_matches, MAX_MATCH);
    }
    end = clock();
    t_dfa = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    /* Benchmark KMP */
    start = clock();
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        kmpSearch(log_payload, bench_pattern,
                  bench_matches, MAX_MATCH);
    }
    end = clock();
    t_kmp = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    /* Find fastest for relative comparison */
    double fastest = t_naive;
    if (t_rk < fastest) fastest = t_rk;
    if (t_dfa < fastest) fastest = t_dfa;
    if (t_kmp < fastest) fastest = t_kmp;

    printf("  ┌────────────────────────────────┬───────────────┬────────────┐\n");
    printf("  │ Algorithm                      │ Time (ms)     │ Relative   │\n");
    printf("  ├────────────────────────────────┼───────────────┼────────────┤\n");
    printf("  │ Naive (Brute-Force)            │ %10.3f ms │   %5.2fx   │\n",
           t_naive, t_naive / fastest);
    printf("  │ Rabin-Karp (Rolling Hash)      │ %10.3f ms │   %5.2fx   │\n",
           t_rk, t_rk / fastest);
    printf("  │ Finite Automaton (DFA)         │ %10.3f ms │   %5.2fx   │\n",
           t_dfa, t_dfa / fastest);
    printf("  │ KMP (Zero-Backtrack)           │ %10.3f ms │   %5.2fx   │\n",
           t_kmp, t_kmp / fastest);
    printf("  └────────────────────────────────┴───────────────┴────────────┘\n");

    printf("\n  Interpretation:\n");
    printf("  • Naive:  O(nm) — simple but slow on adversarial inputs\n");
    printf("  • Rabin-Karp:  Expected O(n+m) — hash-based filtering,\n");
    printf("                 good for multi-pattern scanning\n");
    printf("  • Finite Automaton:  O(n) matching after O(m|Σ|) build —\n");
    printf("                       fastest matching, but expensive setup\n");
    printf("  • KMP:  O(n+m) guaranteed — best balance of speed and\n");
    printf("          memory for real-time threat detection\n");

    printf("\n");
    print_separator();
    printf("  ✅ String Matching & Number Theory module demo complete.\n");
    print_separator();
    printf("\n");

    #undef MAX_MATCH
}
