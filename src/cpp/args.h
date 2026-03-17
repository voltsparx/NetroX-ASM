#pragma once

#include <stdint.h>
#include <stddef.h>

#include "../../include/netrox-asc_abh.h"

constexpr uint8_t SCAN_SYN        = 1;
constexpr uint8_t SCAN_ACK        = 2;
constexpr uint8_t SCAN_FIN        = 3;
constexpr uint8_t SCAN_NULL       = 4;
constexpr uint8_t SCAN_XMAS       = 5;
constexpr uint8_t SCAN_WINDOW     = 6;
constexpr uint8_t SCAN_MAIMON     = 7;
constexpr uint8_t SCAN_UDP        = 8;
constexpr uint8_t SCAN_PING       = 9;
constexpr uint8_t SCAN_SAR        = 10;
constexpr uint8_t SCAN_KIS        = 11;
constexpr uint8_t SCAN_PHANTOM    = 12;
constexpr uint8_t SCAN_CALLBACK   = 13;
constexpr uint8_t SCAN_CONNECT    = 14;
constexpr uint8_t SCAN_IDLE       = 15;
constexpr uint8_t SCAN_IPROTO     = 16;
constexpr uint8_t SCAN_PINGSWEEP  = 17;
constexpr uint8_t SCAN_LIST       = 18;
constexpr uint8_t SCAN_RPC        = 19;
constexpr uint8_t SCAN_SCTP_INIT  = 20;
constexpr uint8_t SCAN_SCTP_ECHO  = 21;
constexpr uint8_t SCAN_FTP_BOUNCE = 22;
constexpr uint8_t SCAN_SCRIPT     = 23;
constexpr uint8_t SCAN_AGGRESSIVE = 24;
constexpr uint8_t SCAN_SEQ        = 25;
constexpr uint8_t SCAN_ICMP_TS    = 26;
constexpr uint8_t SCAN_ICMP_NM    = 27;
constexpr uint8_t SCAN_ARP        = 28;
constexpr uint8_t SCAN_NETBIOS    = 29;
constexpr uint8_t SCAN_MDNS       = 30;
constexpr uint8_t SCAN_SNMP       = 31;
constexpr uint8_t SCAN_SMB        = 32;
constexpr uint8_t SCAN_SSL        = 33;
constexpr uint8_t SCAN_HTTP       = 34;
constexpr uint8_t SCAN_DNS        = 35;
constexpr uint8_t SCAN_NTP        = 36;
constexpr uint8_t SCAN_REDIS      = 37;
constexpr uint8_t SCAN_MEMCACHED  = 38;
constexpr uint8_t SCAN_DEEP       = 39;
constexpr uint8_t SCAN_HEARTBLEED = 40;


constexpr uint8_t SCAN_QUIC      = 41;
constexpr uint8_t SCAN_MQTT      = 42;
constexpr uint8_t SCAN_MODBUS    = 43;
constexpr uint8_t SCAN_S7        = 44;
constexpr uint8_t SCAN_BACNET    = 45;
constexpr uint8_t SCAN_UPNP      = 46;
constexpr uint8_t SCAN_TELNET    = 47;
constexpr uint8_t SCAN_VNC       = 48;
constexpr uint8_t SCAN_RDP       = 49;
constexpr uint8_t SCAN_AMQP      = 50;
constexpr uint8_t SCAN_MSSQL     = 51;
constexpr uint8_t SCAN_MYSQL     = 52;
constexpr uint8_t SCAN_POSTGRES  = 53;
constexpr uint8_t SCAN_MONGO     = 54;
constexpr uint8_t SCAN_ELASTIC   = 55;
constexpr uint8_t SCAN_LDAP      = 56;
constexpr uint8_t SCAN_KERBEROS  = 57;
constexpr uint8_t SCAN_WINRM     = 58;
constexpr uint8_t SCAN_KAFKA     = 59;
constexpr uint8_t SCAN_DNP3      = 60;

bool parse_args(int argc, char** argv, ScanConfig& cfg);
void print_usage();

// Internal helpers (also usable by targets.cpp)
uint32_t parse_ip(const char* s);        // returns 0 on error
bool     parse_cidr(const char* s, uint32_t& base, uint8_t& prefix_len);
bool     parse_port_spec(const char* s, ScanConfig& cfg);
uint8_t  parse_scan_mode(const char* s); // returns SCAN_xxx constant
uint64_t parse_timespec(const char* s);  // returns microseconds
bool     parse_ip_port(const char* s, uint32_t& ip, uint16_t& port);

// Target-related extras
const char* get_iL_path();
const char* get_excludefile_path();
const uint32_t* get_exclude_list(size_t& count);
bool get_help_mode();
bool get_about_mode();
bool get_echo_mode();
bool get_wizard_mode();
bool get_no_color();
bool get_iflist_mode();
bool get_version_mode();
bool get_skip_discovery();
bool get_ping_only_mode();
uint8_t get_disc_icmp_type();
bool get_traceroute_mode();
uint32_t get_random_count();
uint64_t get_min_rtt_timeout();
uint64_t get_max_rtt_timeout();
uint64_t get_initial_rtt_timeout();
uint32_t get_min_hostgroup();
uint32_t get_max_hostgroup();





const char* get_filter_expr();
bool get_silent_mode();
bool get_offline_mode();
const char* get_stats_file();
bool get_iL_from_stdin();

