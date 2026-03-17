// Q1: asm_scan_run
// Q2: ScanConfig
// Q3: on_port_result callback (cfg->on_port_result)
// Q4: 7-color rule: BRIGHT RED=open ports/STORM, BRIGHT YELLOW=filtered+alerts,
//     BRIGHT GREEN=success/STABLE/INTACT, DARK CYAN=section headers/[CB] prefix,
//     BRIGHT WHITE=emphasis, GRAY=metadata, RESET=terminate color.
#pragma once

#include <stdint.h>

// ------------------------------------------------------------------
// Scan result entry -- one per open/filtered port discovered
// ------------------------------------------------------------------
struct PortResult {
    uint16_t port;
    uint8_t  state;     // 0=closed, 1=open, 2=filtered, 3=open|filtered
    uint8_t  proto;     // 0=tcp, 1=udp, 2=sctp
    uint32_t rtt_ns;    // RTT in nanoseconds (0 if unknown)
    char     service[32];
    char     version[64];
        char     reason[16];  // "syn-ack", "rst", "no-resp", "icmp-unreach"

    uint8_t  tls_version;       // 0=none,1=SSLv3,2=TLS10,3=TLS11,4=TLS12,5=TLS13
    uint8_t  heartbleed_vuln;   // 1=vulnerable
    char     banner[256];       // raw banner text
    char     cert_cn[128];      // TLS cert CN
    char     netbios_name[32];  // NetBIOS hostname
    char     netbios_wg[32];    // NetBIOS workgroup
    uint8_t  smb_v1;            // 1=SMBv1 detected
    char     finding[128];      // deep probe finding
};

// ------------------------------------------------------------------
// Main configuration -- built by C++ arg parser, passed to ASM
// ------------------------------------------------------------------
struct ScanConfig {
    // Target
    // offset 0
    uint32_t   target_ip;
    // offset 4
    uint32_t   target_mask;    // /N notation -- 0xFFFFFFFF = single host
    // offset 8
    uint8_t    cidr_mode;
    // offset 9
    uint8_t    ipv6_mode;

    // Port range
    // offset 10
    uint16_t   start_port;
    // offset 12
    uint16_t   end_port;
    // offset 16
    uint16_t*  port_list;       // NULL if range mode
    // offset 24
    uint16_t   port_list_count;
    // offset 26
    uint8_t    top_ports_mode;
    // offset 28
    uint16_t   top_ports_n;
    // offset 30
    uint8_t    sequential_mode;
    // offset 31
    uint8_t    fast_mode;

    // Scan mode
    // offset 32
    uint8_t    scan_mode;       // SCAN_xxx constants from constants.inc
    // offset 33
    uint8_t    engine_mode;     // ENGINE_xxx constants

    // Timing
    // offset 36
    uint32_t   rate_pps;
    // offset 40
    uint32_t   scan_delay_us;
    // offset 44
    uint32_t   max_scan_delay_us;
    // offset 48
    uint32_t   min_rate;
    // offset 52
    uint16_t   min_parallel;
    // offset 54
    uint16_t   max_parallel;
    // offset 56
    uint64_t   host_timeout_us;
    // offset 64
    uint8_t    retry_count;
    // offset 65
    uint8_t    timing_template;
    // offset 66
    uint8_t    stab_enabled;

    // Output flags
    // offset 67
    uint8_t    json_mode;
    // offset 68
    uint8_t    csv_mode;
    // offset 69
    uint8_t    quiet_mode;      // --open
    // offset 70
    uint8_t    reason_mode;
    // offset 71
    uint8_t    packet_trace;
    // offset 72
    uint8_t    verbosity;
    // offset 73
    uint8_t    debug_level;
    // offset 74
    uint8_t    bench_mode;
    // offset 80
    char*      output_file;     // -oN path or NULL
    // offset 88
    char*      oX_path;
    // offset 96
    char*      oG_path;

    // Detection
    // offset 104
    uint8_t    os_detect;
    // offset 105
    uint8_t    version_enabled;
    // offset 106
    uint8_t    version_intensity;
    // offset 107
    uint8_t    banners_mode;

    // Network / packet
    // offset 108
    char       iface[16];
    // offset 124
    uint32_t   local_ip;
    // offset 128
    uint8_t    frag_mode;
    // offset 130
    uint16_t   frag_mtu;
    // offset 132
    uint32_t   spoof_src_ip;
    // offset 136
    uint8_t    custom_ttl;
    // offset 137
    uint8_t    badsum_mode;
    // offset 140
    uint32_t   decoy_list[8];
    // offset 172
    uint8_t    decoy_count;
    // offset 173
    uint8_t    decoy_me_pos;
    // offset 174
    uint8_t    custom_data[64];
    // offset 238
    uint8_t    custom_data_len;
    // offset 239
    uint8_t    random_data_len;
    // offset 240
    uint16_t   src_port;

    // Special scan params
    // offset 244
    uint32_t   zombie_ip;
    // offset 248
    uint16_t   zombie_port;
    // offset 252
    uint32_t   ftp_proxy_ip;
    // offset 256
    uint16_t   ftp_proxy_port;

    // Callbacks -- C++ functions the ASM engines call to report results
    // offset 264
    void  (*on_port_result)(const PortResult* r);   // called per result
    // offset 272
    void  (*on_host_up)(uint32_t ip);               // called when host responds
    // offset 280
        void  (*on_scan_done)(void);                    // called at scan end

    // === TX/RX Threading (masscan model) ===
    // offset 288
    uint8_t    tx_rx_split;       // 1=separate TX/RX threads, 0=epoll model
    // offset 289
    uint8_t    use_tx_ring;       // 1=PACKET_TX_RING, 0=raw sendto
    // offset 290
    uint16_t   shard_id;          // 0=disabled, 1..N = shard number
    // offset 292
    uint16_t   shard_total;       // total number of shards (must be >0)
    // offset 296
    uint64_t   index_start;       // scan index range start (shard support)
    // offset 304
    uint64_t   index_end;         // scan index range end

    // === Extended output ===
    // offset 312
    uint8_t    output_format;     // 0=text,1=json,2=csv,3=xml,4=binary,5=list
    // offset 313
    uint8_t    output_append;     // 1=O_APPEND on output files

    // === Deep scan ===
    // offset 314
    uint8_t    deep_level;        // 0=off,1=banners,2=fingerprint,3=full
    // offset 315
    uint8_t    heartbleed_check;  // 1=test SSL ports for Heartbleed
    // offset 316
    uint8_t    readscan_mode;     // 1=read binary scan file, not scan
    // offset 317
    uint8_t    _pad0[7];          // align to 8 bytes for pointer
    // offset 324
    char*      readscan_path;     // path to binary scan file

    // === Knowledge base (opaque C++ pointer) ===
    // offset 332
    void*      host_kb;           // KnowledgeBase* cast to void*

    // === New callback ===
    // offset 340
    void  (*on_scan_progress)(uint64_t current, uint64_t total); // progress


    // === v3 additions ===
    // offset 348
    uint8_t    cooldown_secs;    // RX cooldown after TX done (default 8)
    // offset 349
    uint8_t    silent_mode;      // 1 = suppress all non-result output
    // offset 350
    uint8_t    offline_mode;     // 1 = build packets but do not send
    // offset 351
    uint8_t    probes_per_target; // probes per target (1-5)
    // offset 352
    uint32_t   max_results;      // stop after N results (0=unlimited)
    // offset 356
    uint32_t   max_runtime_secs; // stop after N seconds (0=unlimited)
    // offset 360
    uint64_t   scan_seed;        // 0=random, else fixed seed
    // offset 368
    uint64_t   bandwidth_bps;    // rate in bits/sec (0=use rate_pps)
    // offset 376
    char*      stats_file;       // stats output file (NULL=stderr)
    // offset 384
    uint8_t    iL_from_stdin;    // 1 = read targets from stdin
    // offset 385
    uint8_t    _pad1[7];
};

#ifdef __cplusplus
extern "C" {
#endif

// Initialize raw socket, TSC, rate control. Call before asm_scan_run.
// Returns 0 on success, negative errno on failure.
int  asm_scan_init(ScanConfig* cfg);

// Run the scan. Blocks until complete. Calls cfg->on_port_result()
// for each discovered port. Returns total open port count.
int  asm_scan_run(ScanConfig* cfg);

// Called by C++ after asm_scan_init to resolve local IP.
// Writes into cfg->local_ip.
int  asm_get_local_ip(ScanConfig* cfg);

// Host discovery probe -- returns 1 if host responds, 0 if not.
int  asm_host_probe(uint32_t target_ip, ScanConfig* cfg);

// Returns current TSC frequency in Hz (calibrated on init).
uint64_t asm_get_tsc_hz(void);

// Clean shutdown: close sockets, flush buffers.
void asm_scan_cleanup(void);

int      asm_start_tx_thread(ScanConfig* cfg);
int      asm_start_rx_thread(ScanConfig* cfg);
uint64_t asm_get_scan_index(void);
int      asm_drain_results(ScanConfig* cfg);
int      asm_setup_tx_ring(ScanConfig* cfg);

#ifdef __cplusplus
}
#endif

// sizeof(ScanConfig) = 392 bytes

