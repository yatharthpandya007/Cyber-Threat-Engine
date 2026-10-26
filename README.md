# 🛡️ Cybersecurity Threat Detection & Operations Engine

[![Language](https://img.shields.io/badge/Language-C11-00599C.svg?style=flat&logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/)
[![Build](https://img.shields.io/badge/Build-CMake%203.10+-brightgreen.svg)](https://cmake.org/)
[![Architecture](https://img.shields.io/badge/Binary-Universal%20(Apple%20Silicon%20%2B%20Intel)-orange.svg)](https://developer.apple.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An industry-style security analytics engine and Security Operations Center (SOC) platform written from scratch in pure, portable **C11**. It bridges theoretical computer science with practical network defense by mapping 10 major algorithm paradigms directly to operational cybersecurity challenges.

---

## 🚀 Key Features

* **Real-time Threat Correlation:** Evaluates streaming log events against known attack vectors (SQL Injection, SSH Brute Force, Directory Traversal, EternalBlue SMB Exploit).
* **Volumetric DDoS Detection:** Employs a divide-and-conquer Maximum Subarray algorithm to isolate the exact multi-minute window of peak traffic surges.
* **Network Graph Optimization:** Models network hosts and lateral movement paths using Dijkstra, Bellman-Ford, Floyd-Warshall, and Spanning Tree algorithms.
* **SOC Resource Dispatching:** Leverages greedy scheduling, dynamic programming, and Branch-and-Bound algorithms to optimize analyst assignment and incident response.
* **High-Speed Payload Inspection:** Benchmarks four string-matching algorithms (Naive, Rabin-Karp, DFA, KMP) across packet payloads.
* **Zero External Dependencies:** Built using standard ISO C11 libraries, compiling into a standalone native binary without runtime overhead.
* **Portable Native macOS App:** Packaged into a self-contained Apple Universal Binary (`.app`) that runs on both Apple Silicon (M1/M2/M3/M4) and Intel Macs.

---

## 📊 Algorithm to Cybersecurity Mapping

| Paradigm | Algorithm | Cybersecurity Domain Application | Asymptotic Time |
| :--- | :--- | :--- | :--- |
| **Data Models** | Typed Records (`LogEntry`, `Host`, `Alert`) | Validated network telemetry & priority scoring | $O(1)$ |
| **Sorting** | Quick Sort | Chronological event timeline reconstruction | $O(n \log n)$ avg |
| **Sorting** | Stable Merge Sort | Incident triage ranking by severity descending | $\Theta(n \log n)$ |
| **Searching** | Binary Search (Iterative & Recursive) | Instantaneous Unix Epoch log querying | $O(\log n)$ |
| **Indexing** | Binary Search Tree (BST) | Dynamic host IP and event timestamp indexing | $O(\log n)$ avg |
| **Divide & Conquer** | Maximum Subarray | Volumetric DDoS attack window isolation | $\Theta(n \log n)$ |
| **Divide & Conquer** | Fast Modular Exponentiation | Cryptographic key derivation ($base^{exp} \bmod m$) | $O(\log n)$ |
| **Divide & Conquer** | Celebrity Elimination | Honeypot / network sinkhole discovery | $O(n)$ |
| **Divide & Conquer** | Strassen Matrix Multiplication | 2-hop attack graph reachability ($A^2$) | $\Theta(n^{2.807})$ |
| **Greedy** | Activity Selection | Conflict-free incident response task scheduling | $O(n \log n)$ |
| **Greedy** | Interval Partitioning | Optimal 24/7 SOC analyst shift sizing | $O(n \log n)$ |
| **Greedy** | Huffman Coding | Lossless log payload archival compression | $O(n \log n)$ |
| **Greedy** | Dijkstra's Algorithm | Fastest attacker lateral movement path | $O(V^2)$ |
| **Greedy** | Prim's & Kruskal's MST | Minimum-cost encrypted network backbone | $O(E \log E)$ |
| **Dynamic Prog.** | 0/1 Knapsack | Budget-constrained defensive tool deployment | $O(nW)$ |
| **Dynamic Prog.** | Matrix Chain Multiplication | Optimal multi-table log correlation join order | $O(n^3)$ |
| **Dynamic Prog.** | Longest Common Subsequence (LCS) | Polymorphic attack signature variant matching | $O(mn)$ |
| **Dynamic Prog.** | Optimal BST | Query-frequency-tuned IP address search | $O(n^3)$ |
| **Dynamic Prog.** | Bellman-Ford | Shortest path with trust penalties & negative cycle detection | $O(VE)$ |
| **Dynamic Prog.** | Floyd-Warshall | All-pairs threat blast radius proximity matrix | $O(V^3)$ |
| **Dynamic Prog.** | Bounded TSP (Held-Karp) | Optimal physical audit inspection patrol route | $O(n^2 2^n)$ |
| **Backtracking** | N-Queens | Non-conflicting firewall rule zone placement | $O(N!)$ |
| **Backtracking** | Subset Sum | Forensic data exfiltration volume reconstruction | $O(2^n)$ |
| **Branch & Bound** | FIFO, LIFO, Least-Cost B&B | Optimal analyst-to-incident assignment with pruning | $O(n! n)$ |
| **Network Flow** | Ford-Fulkerson (Edmonds-Karp) | Network link bandwidth bottleneck & max throughput | $O(VE^2)$ |
| **Network Flow** | Maximum Bipartite Matching | Analyst-to-breach qualified 1:1 pairing | $O(VE^2)$ |
| **Number Theory** | Chinese Remainder Theorem | Distributed master cryptographic key reconstruction | $O(k \log M)$ |
| **Pattern Search** | Naive String Scanner | Baseline raw payload search | $O(nm)$ |
| **Pattern Search** | Rabin-Karp Rolling Hash | Multi-pattern hash filtering | $O(n+m)$ avg |
| **Pattern Search** | Finite Automaton (DFA) | Streaming state-machine signature detection | $O(n)$ |
| **Pattern Search** | Knuth-Morris-Pratt (KMP) | Zero-backtrack real-time signature matching | $O(n+m)$ |

---

## 📦 Download & Running the App

### Option 1: macOS Double-Click App (Pre-built)
1. Download **`CyberThreatEngine_macOS_Universal.zip`** from the [Releases](../../releases) tab.
2. Double-click to extract **`CyberThreatEnginePortable.app`**.
3. Double-click the app icon to open the interactive terminal console.

### Option 2: Build from Source (macOS, Linux, Windows)

#### Prerequisites:
* C11 compiler (`clang`, `gcc`, or `MSVC`)
* CMake `>= 3.10`
* `make` or `ninja`

#### Build Instructions:
```bash
git clone https://github.com/<YOUR-USERNAME>/cyber-threat-engine.git
cd cyber-threat-engine
mkdir -p build && cd build
cmake ..
make
```

#### Run CLI:
```bash
# Launch interactive terminal menu
./ThreatEngine

# Run complete end-to-end showcase
./ThreatEngine --all

# Run benchmark performance suite
./ThreatEngine --benchmark

# View mathematical recurrence proofs & complexity matrix
./ThreatEngine --report

# Run an individual module
./ThreatEngine --module dc
./ThreatEngine --module flow
./ThreatEngine --module strings
```

---

## 📈 Benchmarks

Empirical performance measured across stress test runs (macOS Apple Silicon):

```text
Log Sorting (N = 1,000 records):
  - Merge Sort (Stable):            0.31 ms / run (Strict O(n log n))
  - Quick Sort by Timestamp:       13.22 ms / run

Payload Pattern Matching (|Text| = 10,000 characters):
  - Naive Scanner:                  0.0417 ms / run
  - Rabin-Karp Rolling Hash:        0.0855 ms / run
  - Finite Automaton (DFA):         0.2433 ms / run
  - Knuth-Morris-Pratt (KMP):       0.0519 ms / run (Zero-backtrack guaranteed)
```

---

## 📄 License
This project is open-source under the MIT License.
