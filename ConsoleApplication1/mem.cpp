// mem.cpp
#include "mem.hpp"
#include "proc.hpp"
#include <vector>
#include <string>
#include <windows.h>
#include <iostream>
#include <sstream>

void __fastcall start_memory_scan(const DWORD pid) {
    auto range = __get_mem_range(pid);
    DWORD_PTR base = range.first;
    DWORD_PTR end = range.second;

    if (base == 0 || end == 0 || end <= base) {
        printf("Cannot determine memory range (pid %u)\n", pid);
        return;
    }

    SIZE_T total = end - base;
    printf("Scanning PID %u: base=0x%p end=0x%p size=%llu bytes\n", pid, (void*)base, (void*)end, (unsigned long long)total);

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed for PID %u (err %u)\n", pid, GetLastError());
        return;
    }

    const SIZE_T chunk = 0x1000 * 16; // 64 KB
    std::vector<char> buffer;
    buffer.resize(chunk);

    for (DWORD_PTR addr = base; addr < end; addr += chunk) {
        SIZE_T toRead = chunk;
        if (addr + toRead > end) toRead = end - addr;

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, buffer.data(), toRead, &bytesRead)) {
            // skip unreadable pages
            // printf("ReadProcessMemory failed at 0x%p (err %u)\n", (void*)addr, GetLastError());
            continue;
        }

        // naive ASCII string search
        size_t curLen = 0;
        std::string cur;
        for (SIZE_T i = 0; i < bytesRead; ++i) {
            unsigned char c = buffer[i];
            if (c >= 0x20 && c <= 0x7E) {
                cur.push_back((char)c);
                curLen++;
            }
            else {
                if (curLen >= MIN_STRING_LENGTH) {
                    printf("Found ASCII string at 0x%p: %s\n", (void*)(addr + i - curLen), cur.c_str());
                }
                cur.clear();
                curLen = 0;
            }
        }
        // tail
        if (curLen >= MIN_STRING_LENGTH) {
            printf("Found ASCII string at 0x%p: %s\n", (void*)(addr + bytesRead - curLen), cur.c_str());
        }
    }

    CloseHandle(hProcess);
}
