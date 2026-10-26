#ifndef CONSTRAINTS_H
#define CONSTRAINTS_H

#include <stdbool.h>
#include <stdint.h>
#include "core/models.h"

// ============================================================================
// VALIDATION CONSTRAINTS & SERVICE LEVEL INDICATORS (SLIs)
// ============================================================================

#define MIN_SEVERITY 1
#define MAX_SEVERITY 10
#define MAX_PORT 65535
#define MAX_ALERT_CONTAINMENT_BUDGET 100

// Measurable Service Indicators (SLIs)
typedef struct {
    double mean_time_to_detect_ms;  // MTTD target < 50ms
    double false_positive_rate;     // FPR target < 2.0%
    double containment_latency_ms;  // Target < 100ms
    uint64_t logs_processed_per_sec;// Throughput target > 10,000 eps
    int total_evaluated;
    int total_threats_flagged;
    int valid_events;
    int rejected_events;
    double total_cpu_time_ms;
} EngineSLIs;

// Global persistent SLI state
extern EngineSLIs g_engineSLIs;

// Validation rules
bool validateLogEntry(const LogEntry* log, char* violationReason, int maxLen);
bool validateHost(const Host* host);

// Threat correlation
int correlateThreats(const LogEntry logs[], int logCount,
                     const Signature signatures[], int sigCount,
                     Alert alerts[], int maxAlerts);

// SLI Reporting
void initializeSLIs(EngineSLIs* sli);
void updateSLIsLive(EngineSLIs* sli, int evaluated, int valid, int rejected, int flagged, double cpu_time_ms);
void printSLIReport(const EngineSLIs* sli);

// Interactive control center
void run_constraints_demos(void);

#endif
