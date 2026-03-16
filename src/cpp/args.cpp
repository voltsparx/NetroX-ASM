#include "args.h"

#include <string_view>
#include <cstring>
#include <cctype>
#include <cstdlib>

static const char* g_iL_path = nullptr;
static const char* g_excludefile_path = nullptr;
static uint32_t g_exclude_list[256];
static size_t g_exclude_count = 0;
static bool g_help_mode = false;
static bool g_about_mode = false;
static bool g_echo_mode = false;
static bool g_wizard_mode = false;
static bool g_no_color = false;
static bool g_iflist_mode = false;
static bool g_version_mode = false;
static bool g_skip_discovery = false;
static bool g_ping_only_mode = false;
static uint8_t g_disc_icmp_type = 8;
static bool g_traceroute_mode = false;
static uint32_t g_random_count = 0;
static uint64_t g_min_rtt_timeout = 0;
static uint64_t g_max_rtt_timeout = 0;
static uint64_t g_initial_rtt_timeout = 0;
static uint32_t g_min_hostgroup = 0;
static uint32_t g_max_hostgroup = 0;

const char* get_iL_path() { return g_iL_path; }
const char* get_excludefile_path() { return g_excludefile_path; }
const uint32_t* get_exclude_list(size_t& count) { count = g_exclude_count; return g_exclude_list; }
bool get_help_mode() { return g_help_mode; }
bool get_about_mode() { return g_about_mode; }
bool get_echo_mode() { return g_echo_mode; }
bool get_wizard_mode() { return g_wizard_mode; }
bool get_no_color() { return g_no_color; }
bool get_iflist_mode() { return g_iflist_mode; }
bool get_version_mode() { return g_version_mode; }
bool get_skip_discovery() { return g_skip_discovery; }
bool get_ping_only_mode() { return g_ping_only_mode; }
uint8_t get_disc_icmp_type() { return g_disc_icmp_type; }
bool get_traceroute_mode() { return g_traceroute_mode; }
uint32_t get_random_count() { return g_random_count; }
uint64_t get_min_rtt_timeout() { return g_min_rtt_timeout; }
uint64_t get_max_rtt_timeout() { return g_max_rtt_timeout; }
uint64_t get_initial_rtt_timeout() { return g_initial_rtt_timeout; }
uint32_t get_min_hostgroup() { return g_min_hostgroup; }
uint32_t get_max_hostgroup() { return g_max_hostgroup; }

static void apply_timing_template(ScanConfig& cfg) {
    if (cfg.timing_template == 0) return;
    switch (cfg.timing_template) {
    case 1:
        cfg.rate_pps = 10;
        cfg.scan_delay_us = 15000000;
        cfg.retry_count = 3;
        break;
    case 2:
        cfg.rate_pps = 100;
        cfg.scan_delay_us = 400000;
        cfg.retry_count = 2;
        break;
    case 3:
        cfg.rate_pps = 1000;
        cfg.scan_delay_us = 15000;
        cfg.retry_count = 2;
        break;
    case 4:
        cfg.rate_pps = 5000;
        cfg.scan_delay_us = 1000;
        cfg.retry_count = 1;
        break;
    case 5:
        cfg.rate_pps = 0;
        cfg.scan_delay_us = 0;
        cfg.retry_count = 0;
        break;
    default:
        cfg.rate_pps = 1;
        cfg.scan_delay_us = 300000000;
        cfg.retry_count = 5;
        break;
    }
}

static uint16_t parse_u16(const char* s) {
    uint32_t v = 0;
    if (!s || !*s) return 0;
    while (*s) {
        if (*s < '0' || *s > '9') return 0;
        v = v * 10 + uint32_t(*s - '0');
        if (v > 65535) return 0;
        s++;
    }
    return static_cast<uint16_t>(v);
}

uint32_t parse_ip(const char* s) {
    if (!s) return 0;
    uint32_t parts[4] = {0,0,0,0};
    int idx = 0;
    const char* p = s;
    while (*p) {
        if (idx > 3) return 0;
        if (*p < '0' || *p > '9') return 0;
        uint32_t v = 0;
        while (*p && *p != '.') {
            if (*p < '0' || *p > '9') return 0;
            v = v * 10 + uint32_t(*p - '0');
            if (v > 255) return 0;
            p++;
        }
        parts[idx++] = v;
        if (*p == '.') p++;
    }
    if (idx != 4) return 0;
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

bool parse_cidr(const char* s, uint32_t& base, uint8_t& prefix_len) {
    const char* slash = std::strchr(s, '/');
    if (!slash) return false;
    std::string_view ip(s, size_t(slash - s));
    char ipbuf[32] = {};
    if (ip.size() >= sizeof(ipbuf)) return false;
    std::memcpy(ipbuf, ip.data(), ip.size());
    uint32_t ipval = parse_ip(ipbuf);
    if (!ipval) return false;
    uint32_t pref = 0;
    const char* p = slash + 1;
    if (!*p) return false;
    while (*p) {
        if (*p < '0' || *p > '9') return false;
        pref = pref * 10 + uint32_t(*p - '0');
        if (pref > 32) return false;
        p++;
    }
    prefix_len = static_cast<uint8_t>(pref);
    uint32_t mask = (pref == 0) ? 0 : (0xFFFFFFFFu << (32 - pref));
    base = ipval & mask;
    return true;
}

bool parse_ip_port(const char* s, uint32_t& ip, uint16_t& port) {
    const char* colon = std::strchr(s, ':');
    if (!colon) return false;
    std::string_view ipstr(s, size_t(colon - s));
    char ipbuf[32] = {};
    if (ipstr.size() >= sizeof(ipbuf)) return false;
    std::memcpy(ipbuf, ipstr.data(), ipstr.size());
    ip = parse_ip(ipbuf);
    if (!ip) return false;
    port = parse_u16(colon + 1);
    return port != 0;
}

static bool parse_port_range(const char* s, uint16_t& start, uint16_t& end) {
    if (!s || !*s) return false;
    if (std::strcmp(s, "-") == 0) { start = 1; end = 65535; return true; }
    const char* dash = std::strchr(s, '-');
    if (!dash) {
        uint16_t v = parse_u16(s);
        if (!v) return false;
        start = end = v;
        return true;
    }
    std::string_view a(s, size_t(dash - s));
    std::string_view b(dash + 1);
    char abuf[16] = {}, bbuf[16] = {};
    if (a.size() >= sizeof(abuf) || b.size() >= sizeof(bbuf)) return false;
    std::memcpy(abuf, a.data(), a.size());
    std::memcpy(bbuf, b.data(), b.size());
    start = parse_u16(abuf);
    end = parse_u16(bbuf);
    if (!start || !end || end < start) return false;
    return true;
}

static bool parse_port_list(const char* s, uint16_t*& list, uint16_t& count) {
    uint16_t tmp[256];
    uint16_t n = 0;
    const char* p = s;
    while (*p) {
        const char* comma = std::strchr(p, ',');
        std::string_view tok = comma ? std::string_view(p, size_t(comma - p)) : std::string_view(p);
        char buf[16] = {};
        if (tok.size() >= sizeof(buf)) return false;
        std::memcpy(buf, tok.data(), tok.size());
        uint16_t v = parse_u16(buf);
        if (!v) return false;
        if (n >= 256) return false;
        tmp[n++] = v;
        if (!comma) break;
        p = comma + 1;
    }
    if (n == 0) return false;
    list = static_cast<uint16_t*>(std::malloc(n * sizeof(uint16_t)));
    if (!list) return false;
    std::memcpy(list, tmp, n * sizeof(uint16_t));
    count = n;
    return true;
}

bool parse_port_spec(const char* s, ScanConfig& cfg) {
    if (std::strchr(s, ',')) {
        uint16_t* list = nullptr;
        uint16_t count = 0;
        if (!parse_port_list(s, list, count)) return false;
        cfg.port_list = list;
        cfg.port_list_count = count;
        return true;
    }
    uint16_t start = 0, end = 0;
    if (!parse_port_range(s, start, end)) return false;
    cfg.start_port = start;
    cfg.end_port = end;
    return true;
}

uint8_t parse_scan_mode(const char* s) {
    if (!s) return 0;
    char buf[32] = {};
    size_t len = std::strlen(s);
    if (len >= sizeof(buf)) return 0;
    for (size_t i = 0; i < len; ++i) buf[i] = char(std::tolower(s[i]));

    if (std::strcmp(buf, "syn") == 0) return SCAN_SYN;
    if (std::strcmp(buf, "ack") == 0) return SCAN_ACK;
    if (std::strcmp(buf, "fin") == 0) return SCAN_FIN;
    if (std::strcmp(buf, "null") == 0) return SCAN_NULL;
    if (std::strcmp(buf, "xmas") == 0) return SCAN_XMAS;
    if (std::strcmp(buf, "window") == 0) return SCAN_WINDOW;
    if (std::strcmp(buf, "maimon") == 0) return SCAN_MAIMON;
    if (std::strcmp(buf, "udp") == 0) return SCAN_UDP;
    if (std::strcmp(buf, "ping") == 0) return SCAN_PING;
    if (std::strcmp(buf, "sar") == 0) return SCAN_SAR;
    if (std::strcmp(buf, "kis") == 0) return SCAN_KIS;
    if (std::strcmp(buf, "phantom") == 0) return SCAN_PHANTOM;
    if (std::strcmp(buf, "callback") == 0) return SCAN_CALLBACK;
    if (std::strcmp(buf, "connect") == 0) return SCAN_CONNECT;
    if (std::strcmp(buf, "idle") == 0) return SCAN_IDLE;
    if (std::strcmp(buf, "iproto") == 0) return SCAN_IPROTO;
    if (std::strcmp(buf, "pingsweep") == 0) return SCAN_PINGSWEEP;
    if (std::strcmp(buf, "list") == 0) return SCAN_LIST;
    if (std::strcmp(buf, "rpc") == 0) return SCAN_RPC;
    if (std::strcmp(buf, "sctp-init") == 0 || std::strcmp(buf, "sctpinit") == 0) return SCAN_SCTP_INIT;
    if (std::strcmp(buf, "sctp-echo") == 0 || std::strcmp(buf, "sctpecho") == 0) return SCAN_SCTP_ECHO;
    if (std::strcmp(buf, "ftp") == 0 || std::strcmp(buf, "ftp-bounce") == 0) return SCAN_FTP_BOUNCE;
    if (std::strcmp(buf, "script") == 0) return SCAN_SCRIPT;
    if (std::strcmp(buf, "aggressive") == 0) return SCAN_AGGRESSIVE;
    if (std::strcmp(buf, "seq") == 0) return SCAN_SEQ;
    if (std::strcmp(buf, "icmp-ts") == 0 || std::strcmp(buf, "icmpts") == 0 || std::strcmp(buf, "icmp_ts") == 0) return SCAN_ICMP_TS;
    if (std::strcmp(buf, "icmp-nm") == 0 || std::strcmp(buf, "icmpnm") == 0 || std::strcmp(buf, "icmp_nm") == 0) return SCAN_ICMP_NM;
    if (std::strcmp(buf, "arp") == 0) return SCAN_ARP;
    return 0;
}

uint64_t parse_timespec(const char* s) {
    if (!s || !*s) return 0;
    uint64_t v = 0;
    const char* p = s;
    while (*p && std::isdigit(static_cast<unsigned char>(*p))) {
        v = v * 10 + uint64_t(*p - '0');
        p++;
    }
    if (*p == 0) return v * 1000ULL;
    if (*p == 'm' && *(p + 1) == 's') return v * 1000ULL;
    if (*p == 's') return v * 1000000ULL;
    if (*p == 'm') return v * 60000000ULL;
    if (*p == 'h') return v * 3600000000ULL;
    return v * 1000ULL;
}

static uint8_t parse_hex_byte(char hi, char lo) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    int a = nib(hi), b = nib(lo);
    if (a < 0 || b < 0) return 0;
    return uint8_t((a << 4) | b);
}

static bool parse_hex_payload(const char* s, uint8_t* out, uint8_t& len) {
    uint8_t count = 0;
    const char* p = s;
    while (*p) {
        while (*p == ':' || *p == ' ') p++;
        if (!p[0] || !p[1]) break;
        if (count >= 64) return false;
        out[count++] = parse_hex_byte(p[0], p[1]);
        p += 2;
    }
    if (count == 0) return false;
    len = count;
    return true;
}

void print_usage() {
    const char* msg =
        "Usage: netrox-asc <target> [options]\n"
        "Try: netrox-asc --help\n";
#ifdef _WIN32
    DWORD written = 0;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)std::strlen(msg), &written, nullptr);
#else
    write(1, msg, std::strlen(msg));
#endif
}

bool parse_args(int argc, char** argv, ScanConfig& cfg) {
    auto next = [&](int& i) -> const char* {
        if (++i >= argc) { print_usage(); std::exit(1); }
        return argv[i];
    };

    for (int i = 1; i < argc; i++) {
        std::string_view arg(argv[i]);

        // --- nmap-compatible short scan flags ---
        if      (arg == "-sS") cfg.scan_mode = SCAN_SYN;
        else if (arg == "-sA") cfg.scan_mode = SCAN_ACK;
        else if (arg == "-sF") cfg.scan_mode = SCAN_FIN;
        else if (arg == "-sN") cfg.scan_mode = SCAN_NULL;
        else if (arg == "-sX") cfg.scan_mode = SCAN_XMAS;
        else if (arg == "-sW") cfg.scan_mode = SCAN_WINDOW;
        else if (arg == "-sM") cfg.scan_mode = SCAN_MAIMON;
        else if (arg == "-sU") cfg.scan_mode = SCAN_UDP;
        else if (arg == "-sT") cfg.scan_mode = SCAN_CONNECT;
        else if (arg == "-sI") cfg.scan_mode = SCAN_IDLE;
        else if (arg == "-sO") cfg.scan_mode = SCAN_IPROTO;
        else if (arg == "-sL") cfg.scan_mode = SCAN_LIST;
        else if (arg == "-sR") cfg.scan_mode = SCAN_RPC;
        else if (arg == "-sY") cfg.scan_mode = SCAN_SCTP_INIT;
        else if (arg == "-sZ") cfg.scan_mode = SCAN_SCTP_ECHO;
        else if (arg == "-sC") { cfg.scan_mode = SCAN_SCRIPT; }
        else if (arg == "-sV") { cfg.version_enabled = 1; cfg.banners_mode = 1; }
        else if (arg == "-sn") { cfg.scan_mode = SCAN_PINGSWEEP; g_ping_only_mode = true; }
        else if (arg == "-PE") { cfg.scan_mode = SCAN_PING; g_disc_icmp_type = 8; }
        else if (arg == "-PP") { cfg.scan_mode = SCAN_ICMP_TS; g_disc_icmp_type = 13; }
        else if (arg == "-PM") { cfg.scan_mode = SCAN_ICMP_NM; g_disc_icmp_type = 17; }
        else if (arg == "-PR") { cfg.scan_mode = SCAN_ARP; }
        else if (arg == "-A")  {
            cfg.scan_mode = SCAN_AGGRESSIVE;
            cfg.os_detect = 1;
            cfg.version_enabled = 1;
            g_traceroute_mode = true;
        }
        else if (arg == "-O") cfg.os_detect = 1;
        else if (arg == "-b") {
            const char* proxy = next(i);
            parse_ip_port(proxy, cfg.ftp_proxy_ip, cfg.ftp_proxy_port);
            cfg.scan_mode = SCAN_FTP_BOUNCE;
        }
        else if (arg == "-sSA") cfg.scan_mode = SCAN_SAR;
        else if (arg == "-sKI") cfg.scan_mode = SCAN_KIS;
        else if (arg == "-sPH") cfg.scan_mode = SCAN_PHANTOM;
        else if (arg == "-sCB") cfg.scan_mode = SCAN_CALLBACK;
        else if (arg == "-sSQ") cfg.scan_mode = SCAN_SEQ;
        else if (arg == "--sar") cfg.scan_mode = SCAN_SAR;
        else if (arg == "--kis") cfg.scan_mode = SCAN_KIS;
        else if (arg == "--phantom") cfg.scan_mode = SCAN_PHANTOM;
        else if (arg == "--callback") cfg.scan_mode = SCAN_CALLBACK;

        else if (arg == "--help" || arg == "-h") g_help_mode = true;
        else if (arg == "--scan") cfg.scan_mode = parse_scan_mode(next(i));
        else if (arg.rfind("--scan=", 0) == 0) cfg.scan_mode = parse_scan_mode(arg.substr(7).data());
        else if (arg == "--rate" || arg == "--max-rate") cfg.rate_pps = (uint32_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--min-rate") cfg.min_rate = (uint32_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--scan-delay") cfg.scan_delay_us = (uint32_t)parse_timespec(next(i));
        else if (arg == "--max-scan-delay") cfg.max_scan_delay_us = (uint32_t)parse_timespec(next(i));
        else if (arg == "--min-rtt-timeout") g_min_rtt_timeout = parse_timespec(next(i));
        else if (arg == "--max-rtt-timeout") g_max_rtt_timeout = parse_timespec(next(i));
        else if (arg == "--initial-rtt-timeout") g_initial_rtt_timeout = parse_timespec(next(i));
        else if (arg == "--max-retries") cfg.retry_count = (uint8_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--version-intensity") cfg.version_intensity = (uint8_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--min-parallelism") cfg.min_parallel = (uint16_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--max-parallelism") cfg.max_parallel = (uint16_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--min-hostgroup") g_min_hostgroup = (uint32_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--max-hostgroup") g_max_hostgroup = (uint32_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--version-light") cfg.version_intensity = 2;
        else if (arg == "--version-all") cfg.version_intensity = 9;
        else if (arg == "--version-trace") { (void)0; }
        else if (arg == "--json") cfg.json_mode = 1;
        else if (arg == "--csv") cfg.csv_mode = 1;
        else if (arg == "--open") cfg.quiet_mode = 1;
        else if (arg == "--reason") cfg.reason_mode = 1;
        else if (arg == "--packet-trace") cfg.packet_trace = 1;
        else if (arg == "--bench") cfg.bench_mode = 1;
        else if (arg == "--banners") { cfg.version_enabled = 1; cfg.banners_mode = 1; }
        else if (arg == "-p") { if (!parse_port_spec(next(i), cfg)) return false; }
        else if (arg == "--top-ports") { cfg.top_ports_mode = 1; cfg.top_ports_n = (uint16_t)std::strtoul(next(i), nullptr, 10); }
        else if (arg == "-F") cfg.fast_mode = 1;
        else if (arg == "-r") cfg.sequential_mode = 1;
        else if (arg == "--os" || arg == "-O") cfg.os_detect = 1;
        else if (arg == "--iface" || arg == "-e") {
            const char* v = next(i);
            std::strncpy(cfg.iface, v, sizeof(cfg.iface)-1);
        }
        else if (arg == "--ttl") cfg.custom_ttl = (uint8_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--badsum") cfg.badsum_mode = 1;
        else if (arg == "-S") cfg.spoof_src_ip = parse_ip(next(i));
        else if (arg == "-g" || arg == "--source-port") cfg.src_port = (uint16_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "-T0" || arg == "-T1" || arg == "-T2" || arg == "-T3" || arg == "-T4" || arg == "-T5") {
            cfg.timing_template = (uint8_t)(arg[2] - '0');
            apply_timing_template(cfg);
        }
        else if (arg == "-iL") g_iL_path = next(i);
        else if (arg == "-iR") g_random_count = (uint32_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "-oN") cfg.output_file = const_cast<char*>(next(i));
        else if (arg == "-oX") cfg.oX_path = const_cast<char*>(next(i));
        else if (arg == "-oG") cfg.oG_path = const_cast<char*>(next(i));
        else if (arg == "-oS") { (void)next(i); }
        else if (arg == "-oA") {
            const char* base = next(i);
            // handled by main.cpp (derive paths)
            cfg.output_file = const_cast<char*>(base);
        }
        else if (arg == "-v") { if (cfg.verbosity < 2) cfg.verbosity++; }
        else if (arg == "-vv") cfg.verbosity = 2;
        else if (arg == "-d") { if (cfg.debug_level < 2) cfg.debug_level++; }
        else if (arg == "-dd") cfg.debug_level = 2;
        else if (arg == "--data") {
            uint8_t len = 0;
            if (parse_hex_payload(next(i), cfg.custom_data, len)) cfg.custom_data_len = len;
        }
        else if (arg == "--data-string") {
            const char* s = next(i);
            size_t n = std::strlen(s);
            if (n > sizeof(cfg.custom_data)) n = sizeof(cfg.custom_data);
            std::memcpy(cfg.custom_data, s, n);
            cfg.custom_data_len = (uint8_t)n;
        }
        else if (arg == "--excludefile") g_excludefile_path = next(i);
        else if (arg == "--exclude") {
            const char* s = next(i);
            g_exclude_count = 0;
            const char* p = s;
            while (*p && g_exclude_count < 256) {
                const char* comma = std::strchr(p, ',');
                std::string_view tok = comma ? std::string_view(p, size_t(comma - p)) : std::string_view(p);
                char buf[32] = {};
                if (tok.size() >= sizeof(buf)) break;
                std::memcpy(buf, tok.data(), tok.size());
                uint32_t ip = parse_ip(buf);
                if (ip) g_exclude_list[g_exclude_count++] = ip;
                if (!comma) break;
                p = comma + 1;
            }
        }
        else if (arg == "--wizard") g_wizard_mode = true;
        else if (arg == "--about") g_about_mode = true;
        else if (arg == "--echo") g_echo_mode = true;
        else if (arg == "--no-color") g_no_color = true;
        else if (arg == "--iflist") g_iflist_mode = true;
        else if (arg == "-V") g_version_mode = true;
        else if (arg == "-Pn") g_skip_discovery = true;
        else if (arg == "--engine") cfg.engine_mode = (uint8_t)std::strtoul(next(i), nullptr, 10);
        else if (arg == "--depth") cfg.top_ports_n = (uint16_t)std::strtoul(next(i), nullptr, 10);
        else {
            // target
            uint32_t ip = parse_ip(arg.data());
            if (ip) cfg.target_ip = ip;
            else {
                print_usage();
                return false;
            }
        }
    }
    return true;
}

