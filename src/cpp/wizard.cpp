#include "wizard.h"
#include "args.h"
#include "output.h"
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static bool read_line(char* buf, size_t maxlen) {
#ifdef _WIN32
    DWORD read = 0;
    if (!ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), buf, (DWORD)(maxlen - 1), &read, nullptr)) return false;
    if (read == 0) return false;
    buf[read] = 0;
#else
    ssize_t n = read(0, buf, maxlen - 1);
    if (n <= 0) return false;
    buf[n] = 0;
#endif
    // trim CR/LF
    for (size_t i = 0; buf[i]; ++i) {
        if (buf[i] == '\r' || buf[i] == '\n') { buf[i] = 0; break; }
    }
    return true;
}

ScanConfig run_wizard() {
    ScanConfig cfg = {};
    out_str("  NetroX-ASC Wizard\n");
    out_str("  -----------------\n");

    char line[256] = {};
    out_str("  Target IP or CIDR: ");
    if (!read_line(line, sizeof(line))) return cfg;
    uint32_t base = 0; uint8_t pref = 0;
    if (parse_cidr(line, base, pref)) {
        cfg.target_ip = base;
        cfg.target_mask = pref;
        cfg.cidr_mode = 1;
    } else {
        cfg.target_ip = parse_ip(line);
    }

    out_str("  Port range (e.g. 1-1000, or press Enter for top 1000): ");
    read_line(line, sizeof(line));
    if (line[0] == 0) {
        cfg.top_ports_mode = 1;
        cfg.top_ports_n = 1000;
    } else {
        parse_port_spec(line, cfg);
    }

    out_str("  Scan type [syn/udp/connect/sar/kis/phantom/aggressive]: ");
    read_line(line, sizeof(line));
    if (line[0]) cfg.scan_mode = parse_scan_mode(line);
    else cfg.scan_mode = SCAN_SYN;

    out_str("  Rate (packets/sec, 0=unlimited): ");
    read_line(line, sizeof(line));
    if (line[0]) cfg.rate_pps = (uint32_t)std::strtoul(line, nullptr, 10);

    out_str("  OS detection? [y/n]: ");
    read_line(line, sizeof(line));
    if (line[0] == 'y' || line[0] == 'Y') cfg.os_detect = 1;

    out_str("  Enable stabilizer? [y/n]: ");
    read_line(line, sizeof(line));
    if (line[0] == 'y' || line[0] == 'Y') cfg.stab_enabled = 1;

    out_str("\n  --- Scan Summary ---\n");
    out_str("  Mode: "); out_str(scan_mode_name(cfg.scan_mode)); out_str("\n");
    out_str("  Start scan? [y/n]: ");
    read_line(line, sizeof(line));
    if (!(line[0] == 'y' || line[0] == 'Y')) {
        ScanConfig empty = {};
        return empty;
    }
    return cfg;
}

