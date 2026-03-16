#include "output.h"
#include "color.h"

#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static char g_outbuf[131072];
static size_t g_outpos = 0;

void out_raw(const char* s, size_t len) {
    if (len == 0) return;
    if (g_outpos + len >= sizeof(g_outbuf)) {
        buf_flush();
    }
    if (len >= sizeof(g_outbuf)) {
#ifdef _WIN32
        DWORD written = 0;
        WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), s, (DWORD)len, &written, nullptr);
#else
        write(1, s, len);
#endif
        return;
    }
    std::memcpy(g_outbuf + g_outpos, s, len);
    g_outpos += len;
}

void out_str(const char* s) { out_raw(s, std::strlen(s)); }
void out_char(char c) { out_raw(&c, 1); }

void out_uint(uint64_t n) {
    char tmp[20];
    int i = 19;
    tmp[i] = 0;
    do {
        tmp[--i] = char('0' + (n % 10));
        n /= 10;
    } while (n);
    out_raw(tmp + i, 19 - i);
}

void buf_flush() {
    if (g_outpos == 0) return;
#ifdef _WIN32
    DWORD written = 0;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), g_outbuf, (DWORD)g_outpos, &written, nullptr);
#else
    write(1, g_outbuf, g_outpos);
#endif
    g_outpos = 0;
}

const char* scan_mode_name(uint8_t mode) {
    switch (mode) {
    case SCAN_SYN: return "syn";
    case SCAN_ACK: return "ack";
    case SCAN_FIN: return "fin";
    case SCAN_NULL: return "null";
    case SCAN_XMAS: return "xmas";
    case SCAN_WINDOW: return "window";
    case SCAN_MAIMON: return "maimon";
    case SCAN_UDP: return "udp";
    case SCAN_PING: return "ping";
    case SCAN_SAR: return "sar";
    case SCAN_KIS: return "kis";
    case SCAN_PHANTOM: return "phantom";
    case SCAN_CALLBACK: return "callback";
    case SCAN_CONNECT: return "connect";
    case SCAN_IDLE: return "idle";
    case SCAN_IPROTO: return "iproto";
    case SCAN_PINGSWEEP: return "pingsweep";
    case SCAN_LIST: return "list";
    case SCAN_RPC: return "rpc";
    case SCAN_SCTP_INIT: return "sctp-init";
    case SCAN_SCTP_ECHO: return "sctp-echo";
    case SCAN_FTP_BOUNCE: return "ftp";
    case SCAN_SCRIPT: return "script";
    case SCAN_AGGRESSIVE: return "aggressive";
    case SCAN_SEQ: return "seq";
    case SCAN_ICMP_TS: return "icmp-ts";
    case SCAN_ICMP_NM: return "icmp-nm";
    case SCAN_ARP: return "arp";
    default: return "unknown";
    }
}

void print_banner() {
    const char* banner =
        "   _  __    __           _  __    ___   _________\n"
        "  / |/ /__ / /________  | |/_/___/ _ | / __/ ___/\n"
        " /    / -_) __/ __/ _ \\_>  </___/ __ |_/ \\ /__  \n"
        "/_/|_/\\__/\\__/_/  \\___/_/|_|   /_/ |_/___/\\___/  \n";
    out_str(banner);
}

void print_help() {
    const char* help =
        "+----------------------------------------------------------+\n"
        "|            NetroX-ASC  --  Full Help                    |\n"
        "+----------------------------------------------------------+\n"
        "TARGET SPECIFICATION:\n"
        "  <target>            IP, hostname, or CIDR (192.168.1.0/24)\n"
        "  -iL <file>          Read targets from file (one per line)\n"
        "  -iR <n>             Scan N random targets\n"
        "  --exclude <hosts>   Exclude comma-separated IPs/CIDRs\n"
        "  --excludefile <f>   Exclude hosts listed in file\n\n"
        "HOST DISCOVERY:\n"
        "  -sn                 Ping scan only -- no port scan\n"
        "  -Pn                 Skip discovery -- treat all hosts as up\n"
        "  -PS[ports]          TCP SYN discovery probe (default: 80)\n"
        "  -PA[ports]          TCP ACK discovery probe\n"
        "  -PU[ports]          UDP discovery probe (default: 40125)\n"
        "  -PE / -PP / -PM     ICMP echo / timestamp / netmask probe\n"
        "  -PO[protocols]      IP protocol ping\n"
        "  -n                  Never resolve DNS\n"
        "  -R                  Always resolve DNS\n"
        "  --dns-servers <s>   Use custom DNS servers\n"
        "  --system-dns        Use OS resolver\n"
        "  --traceroute        Trace hop path after scan\n\n"
        "SCAN TECHNIQUES:\n"
        "  --scan syn          TCP SYN scan  (default, requires root)\n"
        "  --scan connect      TCP Connect scan (no root needed)\n"
        "  --scan ack          TCP ACK scan (firewall mapping)\n"
        "  --scan window       TCP Window scan\n"
        "  --scan maimon       TCP Maimon scan (FIN/ACK)\n"
        "  --scan fin          TCP FIN scan (stealth)\n"
        "  --scan null         TCP NULL scan (stealth)\n"
        "  --scan xmas         TCP XMAS scan (FIN+PSH+URG)\n"
        "  --scan udp          UDP scan\n"
        "  --scan idle         Idle/zombie scan (use --zombie <ip>)\n"
        "  --scan sctp-init    SCTP INIT scan\n"
        "  --scan sctp-echo    SCTP COOKIE-ECHO scan\n"
        "  --scan iproto       IP protocol scan\n"
        "  --scan ftp          FTP bounce scan (use --ftp-proxy)\n"
        "  --scan ping         ICMP echo scan\n"
        "  --scan pingsweep    Sweep entire subnet for live hosts\n"
        "  --scan list         List targets only (no scan)\n"
        "  --scan arp          ARP host discovery (LAN)\n"
        "  --scan sar          SAR resonance timing scan\n"
        "  --scan kis          KIS impedance scan\n"
        "  --scan phantom      Phantom passive-open scan\n"
        "  --scan callback     Callback-ping secondary monitor\n"
        "  --scan script       Run compiled script probes (-sC)\n"
        "  --scan aggressive   OS + version + script + traceroute\n"
        "  --scan seq          IPID sequence analysis\n"
        "  --scan rpc          RPC portmapper probe\n"
        "  -sC                 Equivalent to --scan script (default)\n"
        "  --script=<name>     Run named script or category\n"
        "  -A                  Aggressive: -O -sV -sC --traceroute\n"
        "  --zombie <ip>       Zombie host for idle scan\n"
        "  --zombie-port <n>   Zombie probe port (default 80)\n"
        "  --ftp-proxy <ip:p>  FTP proxy for bounce scan\n\n"
        "PORT SPECIFICATION:\n"
        "  -p <range>          Port or range: -p22  -p1-1000  -p-\n"
        "  -p <list>           Comma list: -p22,80,443,8080\n"
        "  --exclude-ports <r> Exclude ports from scan\n"
        "  -F                  Fast mode (top 100 ports)\n"
        "  -r                  Sequential port order (no randomize)\n"
        "  --top-ports <n>     Scan N most common ports\n"
        "  --port-ratio <r>    Scan ports with frequency > ratio\n\n"
        "SERVICE / VERSION DETECTION:\n"
        "  -sV / --banners     Banner grab and version detection\n"
        "  --version-intensity <0-9>  Probe depth (default 7)\n"
        "  --version-light     Intensity 2 (faster)\n"
        "  --version-all       Intensity 9 (most thorough)\n"
        "  --version-trace     Show all version probes sent/received\n\n"
        "SCRIPT ENGINE:\n"
        "  --script=<name>     Run script by name or category\n"
        "  --script-args=<kv>  Pass key=value args to scripts\n"
        "  --script-args-file=<f>  Args from file\n"
        "  --script-trace      Show all script data sent/received\n"
        "  --script-help=<n>   Print script description and exit\n\n"
        "OS DETECTION:\n"
        "  -O / --os           Enable OS fingerprinting\n\n"
        "TIMING AND PERFORMANCE:\n"
        "  -T<0-5>             Timing template (0=paranoid 5=insane)\n"
        "  --min-rate <n>      Minimum packets per second\n"
        "  --max-rate <n>      Maximum packets per second\n"
        "  --rate <n>          Alias for --max-rate\n"
        "  --min-parallelism <n>  Minimum concurrent probes\n"
        "  --max-parallelism <n>  Maximum concurrent probes\n"
        "  --min-rtt-timeout <t>  Minimum probe timeout\n"
        "  --max-rtt-timeout <t>  Maximum probe timeout\n"
        "  --initial-rtt-timeout <t>  Starting probe timeout\n"
        "  --max-retries <n>   Max retransmissions (alias --retries)\n"
        "  --host-timeout <t>  Give up on host after this time\n"
        "  --scan-delay <t>    Min delay between probes\n"
        "  --max-scan-delay <t>   Max delay between probes\n"
        "  --stabilize         Adaptive rate control (auto-tune)\n"
        "  --bench             Print benchmark stats after scan\n"
        "  Time format: 500ms  2s  1m  (ms/s/m/h suffix)\n\n"
        "FIREWALL / IDS EVASION AND SPOOFING:\n"
        "  -f / --mtu <val>    Fragment packets (opt. MTU size)\n"
        "  -D <d1,ME,d2,...>   Send decoy packets from fake sources\n"
        "  -S <ip>             Spoof source IP address\n"
        "  -e / --iface <if>   Use specified network interface\n"
        "  -g / --source-port <n>  Use this source port\n"
        "  --proxies <urls>    Route TCP through HTTP/SOCKS4 proxies\n"
        "  --data <hex>        Append custom hex payload to packets\n"
        "  --data-string <s>   Append ASCII string payload\n"
        "  --data-length <n>   Append N random bytes to packets\n"
        "  --ip-options <opt>  Set IP options (R/T/U/S/L)\n"
        "  --ttl <val>         Set IP TTL field manually\n"
        "  --spoof-mac <mac>   Spoof source MAC (with --send-eth)\n"
        "  --badsum            Send packets with broken checksum\n\n"
        "OUTPUT:\n"
        "  -oN <file>          Normal output to file\n"
        "  -oX <file>          XML output to file\n"
        "  -oG <file>          Grepable output to file\n"
        "  -oS <file>          Script-kiddie output to file\n"
        "  -oA <base>          All formats: base.nmap / .xml / .gnmap\n"
        "  --output <file>     Alias for -oN\n"
        "  --json              JSON output to stdout\n"
        "  --csv               CSV output to stdout\n"
        "  -v / -vv            Increase verbosity level\n"
        "  -d / -dd            Increase debug level\n"
        "  --reason            Show why each port is in its state\n"
        "  --open              Show only open ports\n"
        "  --packet-trace      Show every packet sent and received\n"
        "  --iflist            List network interfaces and exit\n"
        "  --append-output     Append to output files (no overwrite)\n"
        "  --resume            Resume an aborted scan\n"
        "  --noninteractive    Disable runtime keyboard input\n"
        "  --stylesheet <path> Add XSL stylesheet to XML output\n"
        "  --webxml            Use online stylesheet in XML output\n"
        "  --no-stylesheet     No stylesheet in XML output\n\n"
        "MISC:\n"
        "  -6                  Enable IPv6 scanning (experimental)\n"
        "  -A                  Aggressive scan (OS+version+script)\n"
        "  --datadir <dir>     Custom data file directory\n"
        "  --send-eth          Send at raw ethernet layer\n"
        "  --send-ip           Send at raw IP layer (default)\n"
        "  --privileged        Assume full privileges\n"
        "  --unprivileged      Assume no raw socket access\n"
        "  -V                  Print version and exit\n"
        "  -h / --help         Show this help\n"
        "  --about             Banner and tool info\n"
        "  --wizard            Interactive scan builder\n"
        "  --explain           Explain current flags and mode\n"
        "  --echo              Print config and exit\n"
        "  --engine <mode>     Engine: async / pipeline / batch\n"
        "  --no-color          Disable color output\n\n"
        "EXAMPLES:\n"
        "  NetroX-ASC 192.168.1.1 -p 1-1000\n"
        "  NetroX-ASC 192.168.1.0/24 --scan syn --top-ports 100\n"
        "  NetroX-ASC 10.0.0.1 -A -T4 -oA result\n"
        "  NetroX-ASC 10.0.0.1 --scan sar -p 1-65535\n"
        "  NetroX-ASC 10.0.0.1 -sC --script=default\n"
        "  NetroX-ASC 10.0.0.1 --scan idle --zombie 10.0.0.5\n"
        "  NetroX-ASC 10.0.0.1 -D 1.2.3.4,ME,5.6.7.8 -T2\n"
        "  NetroX-ASC -iL targets.txt --scan udp -F -oX out.xml\n"
        "  NetroX-ASC 10.0.0.1 -6 -p 80,443\n";
    out_str(help);
    buf_flush();
}

void print_about() {
    print_banner();
    out_str("\nNetroX-ASC - x86_64 NASM network diagnostic engine\n");
    out_str("github.com/voltsparx\n");
}

void explain_print(const ScanConfig& cfg) {
    out_str("=== Explain ===\n");
    out_str("Scan mode: ");
    out_str(scan_mode_name(cfg.scan_mode));
    out_str("\n");
    switch (cfg.scan_mode) {
    case SCAN_SAR:
        out_str("SAR (Synaptic Anomaly Resonance)\n");
        out_str("Timing-based defense classification scan.\n");
        out_str("Measures RTT delta per port against baseline.\n");
        out_str("Reports: UNMONITORED | ACL | STATEFUL | DPI | AI-EDR | PROXY\n");
        out_str("Alias: --sar\n");
        out_str("Example: NetroX-ASC <target> --scan sar -p 1-1000\n");
        break;
    case SCAN_KIS:
        out_str("KIS (Kinetic Impedance Scan)\n");
        out_str("Multi-probe impedance fingerprinting.\n");
        out_str("Detects: virtualization, load balancers, CDN proxies.\n");
        out_str("Outputs a heat map of the target's port texture.\n");
        out_str("Thermal fuse triggers QUANTUM BRAKE on anomaly.\n");
        out_str("Alias: --kis\n");
        out_str("Example: NetroX-ASC <target> --scan kis -p 1-65535\n");
        break;
    case SCAN_PHANTOM:
        out_str("PHANTOM (Phantom Passive-Open)\n");
        out_str("Passive observation + ACK-WIN0 active probing.\n");
        out_str("Detects ports that were already listening before the probe.\n");
        out_str("States: OBSERVED (passive) | CONFIRMED (active) | ABSENT\n");
        out_str("Alias: --phantom\n");
        out_str("Example: NetroX-ASC <target> --scan phantom -p 80,443,8080\n");
        break;
    case SCAN_CALLBACK:
        out_str("CALLBACK (Callback-Ping Monitor)\n");
        out_str("Sends DNS/NTP/ICMP bait, listens for inbound callbacks.\n");
        out_str("Classes: SILENT | STANDARD | RESPONSIVE | DELAYED\n");
        out_str("Alias: --callback\n");
        out_str("Example: NetroX-ASC <target> --scan callback\n");
        break;
    case SCAN_SEQ:
        out_str("SEQ (IPID Sequence Analysis)\n");
        out_str("Analyzes IP ID field increments across repeated probes.\n");
        out_str("Used to find viable zombie hosts for idle scanning.\n");
        out_str("Returns: RANDOM | CONSTANT | INCREMENTAL | BROKEN\n");
        out_str("Example: NetroX-ASC <target> --scan seq\n");
        break;
    default:
        out_str("No extended description for this scan mode.\n");
        break;
    }
    buf_flush();
}

void print_echo_config(const ScanConfig& cfg) {
    out_str("--- [ NetroX-ASC CONFIGURATION ] ---\n");
    out_str("Target     : "); out_uint(cfg.target_ip); out_str("\n");
    out_str("Scan       : "); out_str(scan_mode_name(cfg.scan_mode)); out_str("\n");
    out_str("Ports      : "); out_uint(cfg.start_port); out_str("-"); out_uint(cfg.end_port); out_str("\n");
    out_str("Rate       : "); out_uint(cfg.rate_pps); out_str("\n");
    out_str("Engine     : "); out_uint(cfg.engine_mode); out_str("\n");
}

void write_open_intel(const PortResult&) {
    // Placeholder: Intel annotations are printed by intel.cpp
}

void write_result(const PortResult& r, bool color_on) {
    const char* state = "closed";
    const char* clr = "";
    const char* reset = "";
    if (r.state == 1) { state = "open"; clr = ColorGuard::red(); reset = ColorGuard::reset(); }
    else if (r.state == 2) { state = "filtered"; clr = ColorGuard::yellow(); reset = ColorGuard::reset(); }
    out_uint(r.port);
    out_str("  ");
    if (color_on) out_str(clr);
    out_str(state);
    if (color_on) out_str(reset);
    out_str("  ");
    out_str(r.service);
    out_str("  ");
    out_str(r.version);
    if (r.reason[0]) { out_str("  "); out_str(r.reason); }
    out_str("\n");
}

void print_summary(const ScanConfig&, int open_count, int filtered_count, int closed_count, uint64_t elapsed_ms) {
    out_str(ColorGuard::cyan());
    out_str("--- [ SCAN COMPLETE ] ---\n");
    out_str(ColorGuard::reset());
    out_str("Open     : "); out_str(ColorGuard::red()); out_uint(open_count); out_str(ColorGuard::reset()); out_str("\n");
    out_str("Filtered : "); out_str(ColorGuard::yellow()); out_uint(filtered_count); out_str(ColorGuard::reset()); out_str("\n");
    out_str("Closed   : "); out_uint(closed_count); out_str("\n");
    out_str("Elapsed  : "); out_uint(elapsed_ms); out_str("ms\n");
}

void print_bench(const ScanConfig&, uint64_t pps, uint64_t elapsed_ms) {
    out_str("Benchmark: ");
    out_uint(pps);
    out_str(" pps, ");
    out_uint(elapsed_ms);
    out_str(" ms\n");
}

