#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct DetectionResult {
    unsigned long pid;
    std::string detector_id;    // e.g. "vape_lite" or "generic_agent"
    std::string name;           // human name
    uint64_t address;           // virtual address where match found (0 if unknown)
    std::string snippet;        // matched text or hex snippet
    int confidence;             // 0..100
    std::string note;           // optional note
};

// initialize module (optional base output directory)
void DR_Init(const std::string& out_dir = "out");

// push one detection (thread-safe enough for simple use)
void DR_Report(const DetectionResult& r);

// write results for a PID to disk; if keepInMemory==false clears stored detections for that PID
void DR_SaveAndPrintForPid(unsigned long pid, bool keepInMemory = false);
