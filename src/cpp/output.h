#pragma once

#include <stdint.h>
#include "../../include/netrox-asc_abh.h"

void print_banner();
void print_help();
void print_about();
void explain_print(const ScanConfig& cfg);
void print_echo_config(const ScanConfig& cfg);
void print_summary(const ScanConfig& cfg, int open_count,
                   int filtered_count, int closed_count,
                   uint64_t elapsed_ms);
void print_bench(const ScanConfig& cfg, uint64_t pps,
                 uint64_t elapsed_ms);
void write_result(const PortResult& r, bool color_on);
void write_open_intel(const PortResult& r);
void buf_flush();
void out_raw(const char* s, size_t len);
void out_str(const char* s);
void out_char(char c);
void out_uint(uint64_t n);

const char* scan_mode_name(uint8_t mode);

// JSON / CSV
void json_header(const ScanConfig& cfg);
void json_port(const PortResult& r);
void json_footer(uint64_t elapsed_ms, int open_count, int filtered_count, int closed_count);
void csv_header();
void csv_port(const PortResult& r);

void binary_open(const char* path, bool append);
void binary_write(const PortResult& r, uint64_t scan_start_ts);
void binary_close(uint32_t total_records);
bool binary_readscan(const char* path, ScanConfig& cfg);




