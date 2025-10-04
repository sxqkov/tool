#include "detection_report.hpp"
#include <mutex>
#include <map>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <sstream>

static std::mutex g_mutex;
static std::map<unsigned long, std::vector<DetectionResult>> g_store;
static std::string g_out_dir = "out";

void DR_Init(const std::string& out_dir) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_out_dir = out_dir.empty() ? "out" : out_dir;
    std::error_code ec;
    std::filesystem::create_directories(g_out_dir, ec);
    if (ec) {
        std::cerr << "DR_Init: can't create out dir: " << ec.message() << "\n";
    }
}

void DR_Report(const DetectionResult& r) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_store[r.pid].push_back(r);

    std::ostringstream ss;
    ss << "[DETECT] PID=" << r.pid
        << " id=" << r.detector_id
        << " name=\"" << r.name << "\""
        << " addr=0x" << std::hex << r.address << std::dec
        << " conf=" << r.confidence;
    if (!r.note.empty()) ss << " note=\"" << r.note << "\"";
    if (!r.snippet.empty()) ss << " snippet=\"" << r.snippet << "\"";
    std::cout << ss.str() << std::endl;
}

static std::string time_now_str() {
    using namespace std::chrono;
    auto t = system_clock::to_time_t(system_clock::now());
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm);
    return std::string(buf);
}

void DR_SaveAndPrintForPid(unsigned long pid, bool keepInMemory) {
    std::vector<DetectionResult> copy;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        auto it = g_store.find(pid);
        if (it == g_store.end() || it->second.empty()) {
            return;
        }
        copy = it->second;
        if (!keepInMemory) g_store.erase(it);
    }

    std::string ts = time_now_str();
    std::ostringstream base;
    base << g_out_dir << "/" << pid << "_" << ts;
    std::string outlog = base.str() + ".log";
    std::string outjson = base.str() + ".json";

    std::ofstream fl(outlog, std::ios::out | std::ios::trunc);
    if (fl.is_open()) {
        fl << "PID: " << pid << "\n";
        fl << "Timestamp: " << ts << "\n";
        fl << "Detections: " << copy.size() << "\n\n";
        for (const auto& r : copy) {
            fl << "[" << r.detector_id << "] " << r.name << "\n";
            fl << "  addr: 0x" << std::hex << r.address << std::dec << "\n";
            fl << "  conf: " << r.confidence << "\n";
            if (!r.note.empty()) fl << "  note: " << r.note << "\n";
            if (!r.snippet.empty()) fl << "  snippet: " << r.snippet << "\n";
            fl << "\n";
        }
        fl.close();
        std::cout << "Saved detection log: " << outlog << std::endl;
    }
    else {
        std::cerr << "Failed to open " << outlog << " for writing\n";
    }

    std::ofstream fj(outjson, std::ios::out | std::ios::trunc);
    if (fj.is_open()) {
        fj << "[\n";
        for (size_t i = 0; i < copy.size(); ++i) {
            const auto& r = copy[i];
            fj << "  {\n";
            fj << "    \"pid\": " << r.pid << ",\n";
            fj << "    \"id\": \"" << r.detector_id << "\",\n";
            fj << "    \"name\": \"" << r.name << "\",\n";
            fj << "    \"addr\": \"0x" << std::hex << r.address << std::dec << "\",\n";
            fj << "    \"snippet\": \"" << r.snippet << "\",\n";
            fj << "    \"confidence\": " << r.confidence << ",\n";
            fj << "    \"note\": \"" << r.note << "\"\n";
            fj << "  }";
            if (i + 1 < copy.size()) fj << ",";
            fj << "\n";
        }
        fj << "]\n";
        fj.close();
        std::cout << "Saved detection json: " << outjson << std::endl;
    }
    else {
        std::cerr << "Failed to open " << outjson << " for writing\n";
    }
}
