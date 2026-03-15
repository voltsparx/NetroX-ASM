; ===========================================================================
; NetroX-ASM  |  Windows x86_64  |  Part 1 of 4: Headers, externs, .data, .bss
; ===========================================================================

BITS 64
DEFAULT REL
GLOBAL _start

extern WSAStartup
extern WSACleanup
extern socket
extern closesocket
extern setsockopt
extern sendto
extern recvfrom
extern connect
extern getsockname
extern GetCommandLineA
extern GetStdHandle
extern QueryPerformanceCounter
extern QueryPerformanceFrequency
extern ReadFile
extern WriteFile
extern CreateFileA
extern CloseHandle
extern ExitProcess

%include "../common/parse.inc"
%include "../common/checksum.inc"
%include "../common/packet.inc"
%include "../common/engine.inc"
%include "../common/intelligence.inc"

%define AF_INET          2
%define SOCK_RAW         3
%define SOCK_DGRAM       2
%define IPPROTO_IP       0
%define IPPROTO_TCP      6
%define IPPROTO_UDP      17
%define IP_HDRINCL       2
%define SOL_SOCKET       0xFFFF
%define SO_RCVTIMEO      0x1006
%define INVALID_SOCKET   -1
%define SOCKET_ERROR     -1
%define STD_OUTPUT_HANDLE -11
%define STD_INPUT_HANDLE  -10
%define OUTPUT_BUF_SIZE   131072
%define OUTPUT_FLUSH_THRESHOLD 98304

; ---------------------------------------------------------------------------
; .data
; ---------------------------------------------------------------------------
SECTION .data

usage_msg   db "Usage: netrox-asm.exe <target_ip> [-p port|start-end|-]", 13, 10
            db "       [--rate N] [--scan MODE] [--bench] [--os]", 13, 10
            db "       [--stabilize] [--about] [--wizard] [--callback]", 13, 10
            db "Scan modes: syn ack fin null xmas window maimon udp ping sar kis phantom callback", 13, 10
usage_len   equ $-usage_msg

banner_msg  db "   _  __    __           _  __    ___   ______  ___", 13, 10
            db "  / |/ /__ / /________  | |/_/___/ _ | / __/  |/  /", 13, 10
            db " /    / -_) __/ __/ _ \\_>  </___/ __ |_\\ \\/ /|_/ / ", 13, 10
            db "/_/|_/\\__/\\__/_/  \\___/_/|_|   /_/ |_/___/_/  /_/  ", 13, 10, 13, 10
banner_len  equ $-banner_msg

about_msg   db "author : voltsparx", 13, 10
            db "email  : voltsparx@gmail.com", 13, 10
            db "repo   : https://github.com/voltsparx/NetroX-ASM", 13, 10
            db "github : github.com/voltsparx", 13, 10
about_len   equ $-about_msg

prompt_invalid    db "  Invalid input. Try again.", 10
prompt_invalid_len equ $-prompt_invalid

sar_hdr_msg       db "--- [ SAR RESONANCE SCAN: ", 0
sar_hdr_end       db " ] ---", 10, 0
sar_base_msg      db "Baseline RTT : ", 0
sar_ns_msg        db "ns", 10, 0
sar_limit_msg     db "Synaptic Lmt : ", 0
sar_x_msg         db "x", 10, 0
sar_col_hdr       db "PORT   DELTA    CLASS              BASELINE  MEASURED", 10, 0
sar_col_sep       db "-----  -------  -----------------  --------  --------", 10, 0
sar_sync_msg      db 10, "[SYNAPTIC SYNC] Cognitive load spike. Hard stop.", 10, 0
sar_sum_hdr       db 10, "--- [ SAR COGNITIVE MAP COMPLETE ] ---", 10, 0
sar_sum_audit     db "Ports audited   : ", 0
sar_sum_none      db "Unmonitored     : ", 0
sar_sum_acl       db "ACL/Stateful    : ", 0
sar_sum_dpi       db "DPI detected    : ", 0
sar_sum_ai        db "AI-EDR detected : ", 0
sar_sum_proxy     db "Proxy detected  : ", 0
sar_sum_syncs     db "Synaptic Syncs  : ", 0
sar_status_stab   db "RESONANCE: STABLE", 10, 0
sar_status_coll   db "RESONANCE: COLLAPSING", 10, 0
sar_status_stor   db "RESONANCE: STORM", 10, 0
sar_class_str_0   db "UNMONITORED      ", 0
sar_class_str_1   db "STATELESS-ACL    ", 0
sar_class_str_2   db "STATEFUL-FW      ", 0
sar_class_str_3   db "DPI-LAYER        ", 0
sar_class_str_4   db "AI-EDR           ", 0
sar_class_str_5   db "TRANSPARENT-PROXY", 0
sar_class_ptrs    dq sar_class_str_0, sar_class_str_1, sar_class_str_2
                  dq sar_class_str_3, sar_class_str_4, sar_class_str_5

sar_ntp_payload:
    db 0x1B
    times 47 db 0x00
sar_ntp_len equ $ - sar_ntp_payload

sar_synthetic_payload:
    db 'G','E','T',' '
    db 0x00,0x01,0x00,0x00
    db 0x16,0x03,0x01,0x00
    db 0xDE,0xAD,0xBE,0xEF
sar_synthetic_len equ $ - sar_synthetic_payload

kis_hdr_msg       db "--- [ KIS IMPEDANCE SCAN: ", 0
kis_hdr_end       db " ] ---", 10, 0
kis_ambient_msg   db "Ambient RTT  : ", 0
kis_ttl_msg       db "  TTL=", 0
kis_fuse_ok_msg   db "Thermal Fuse : INTACT", 10, 0
kis_brake_msg     db 10, "[QUANTUM BRAKE] Thermal Fuse blown: ", 0
kis_brake_end     db 10, 0
kis_col_hdr       db "PORT   IMP(ns)  JITTER  STATE     SJS-ID      CONF", 10, 0
kis_col_sep       db "-----  -------  ------  --------  ----------  ----", 10, 0
kis_sum_hdr       db 10, "--- [ KIS IMPEDANCE REPORT ] ---", 10, 0
kis_sum_closed    db "Closed        : ", 0
kis_sum_filtered  db "Filtered      : ", 0
kis_sum_open      db "Open          : ", 0
kis_sum_heavy     db "Open-Heavy    : ", 0
kis_sum_virt      db "Virtualized   : ", 0
kis_sum_unknown   db "Unknown       : ", 0
kis_hmap_hdr      db 10, "--- [ KIS HEAT MAP ] ---", 10, 0
kis_ns_msg        db "ns", 0
kis_pct_msg       db "%", 0

kis_fuse_r1       db "TTL shift detected", 0
kis_fuse_r2       db "Jitter explosion (>10%)", 0
kis_fuse_r3       db "Impedance spike (>5x baseline)", 0
kis_fuse_r4       db "Consecutive timeouts (5+)", 0
kis_fuse_r5       db "Baseline drift (>15%)", 0
kis_fuse_reason_ptrs:
    dq 0
    dq kis_fuse_r1, kis_fuse_r2, kis_fuse_r3
    dq kis_fuse_r4, kis_fuse_r5

kis_svc_str_0     db "UNKNOWN   ", 0
kis_svc_str_1     db "CLOSED    ", 0
kis_svc_str_2     db "FILTERED  ", 0
kis_svc_str_3     db "OPEN      ", 0
kis_svc_str_4     db "HTTP      ", 0
kis_svc_str_5     db "HTTPS     ", 0
kis_svc_str_6     db "SSH       ", 0
kis_svc_str_7     db "DNS       ", 0
kis_svc_str_8     db "DATABASE  ", 0
kis_svc_str_9     db "OPEN-HEAVY", 0
kis_svc_str_10    db "VIRTUAL   ", 0
kis_svc_ptrs:
    dq kis_svc_str_0,  kis_svc_str_1,  kis_svc_str_2
    dq kis_svc_str_3,  kis_svc_str_4,  kis_svc_str_5
    dq kis_svc_str_6,  kis_svc_str_7,  kis_svc_str_8
    dq kis_svc_str_9,  kis_svc_str_10

align 4
kis_sjs_table:
    dw  50,  200,   0,  10, KIS_SVC_CLOSED,   95
    times 13 db 0
    dw 200,  500,   0,  30, KIS_SVC_FILTERED, 80
    times 13 db 0
    dw 500,  900,  10,  40, KIS_SVC_OPEN_RAW, 70
    times 13 db 0
    dw 500,  800,  15,  35, KIS_SVC_HTTP,     75
    times 13 db 0
    dw 600,  950,  20,  50, KIS_SVC_HTTPS,    72
    times 13 db 0
    dw 700, 1100,  25,  60, KIS_SVC_SSH,      78
    times 13 db 0
    dw 500,  750,   5,  20, KIS_SVC_DNS,      82
    times 13 db 0
    dw 800, 1400,  30,  80, KIS_SVC_DB,       68
    times 13 db 0
    dw1200, 2500,  40, 120, KIS_SVC_HEAVY,    65
    times 13 db 0
    dw2500, 9999,  50, 500, KIS_SVC_VIRT,     60
    times 13 db 0
    dw 0, 0, 0, 0, 0, 0
    times 13 db 0

phantom_hdr_msg      db "--- [ PHANTOM SCAN: ", 0
phantom_hdr_end      db " ] ---", 10, 0
phantom_idle_msg     db "Idle RTT   : ", 0
phantom_tev_msg      db "TEV Limit  : ", 0
phantom_tev_pct      db "%", 10, 0
phantom_listen_msg   db "Listen     : ", 0
phantom_listen_sec   db "s (passive discovery)", 10, 0
phantom_passive_msg  db "Passive    : ", 0
phantom_passive_end  db " ports discovered", 10, 0
phantom_col_hdr      db "PORT   STATE            METHOD     RTT(ns)  DEV%", 10, 0
phantom_col_sep      db "-----  ---------------  ---------  -------  ----", 10, 0
phantom_method_ack   db "ACK-WIN0 ", 0
phantom_method_obs   db "OBSERVED ", 0
phantom_state_popen  db "OPEN (PASSIVE) ", 0
phantom_state_open   db "OPEN           ", 0
phantom_state_closed db "CLOSED         ", 0
phantom_state_filt   db "FILTERED       ", 0
phantom_tev_alert    db 10, "[TEV HARD STOP] Processing fatigue detected.", 10, 0
phantom_tev_dev_msg  db "Deviation: ", 0
phantom_tev_thr_msg  db "% (threshold: ", 0
phantom_tev_end_msg  db "%)", 10, 0
phantom_sum_hdr      db 10, "--- [ PHANTOM SCAN COMPLETE ] ---", 10, 0
phantom_sum_passive  db "Passive open  : ", 0
phantom_sum_open     db "Probed open   : ", 0
phantom_sum_closed   db "Closed        : ", 0
phantom_sum_filtered db "Filtered      : ", 0
phantom_sum_tev      db "TEV triggers  : ", 0
phantom_sum_bytes    db "Footprint     : ", 0
phantom_sum_bytes_e  db " bytes", 10, 0
phantom_tev_ok_msg   db "TEV Status    : INTACT", 10, 0
phantom_tev_bad_msg  db "TEV Status    : TRIGGERED", 10, 0
phantom_plus_msg     db "+", 0
phantom_timeout_str  db "timeout", 0
phantom_dash_msg     db "-", 0
phantom_ns_msg       db "ns", 0

cb_hdr_msg        db "--- [ CALLBACK-PING MONITOR: ACTIVE ] ---", 10, 0
cb_proto_msg      db "Protocol    : ", 0
cb_timeout_msg    db "Timeout     : ", 0
cb_ms_msg         db "ms", 10, 0
cb_prefix_msg     db "[CB] ", 0
cb_trigger_syn    db "TRIGGER=SYN  ", 0
cb_trigger_icmp   db "TRIGGER=ICMP ", 0
cb_trigger_udp    db "TRIGGER=UDP  ", 0
cb_proto_dns_str  db "PROTO=DNS  ", 0
cb_proto_ntp_str  db "PROTO=NTP  ", 0
cb_proto_icmp_str db "PROTO=ICMP ", 0
cb_proto_ack_str  db "PROTO=ACK  ", 0
cb_class_silent   db "CLASS=SILENT     ", 0
cb_class_std      db "CLASS=STANDARD   ", 0
cb_class_resp     db "CLASS=RESPONSIVE ", 0
cb_class_delayed  db "CLASS=DELAYED    ", 0
cb_lat_msg        db "LATENCY=", 0
cb_lat_timeout    db "timeout", 0
cb_os_msg         db "OS=", 0
cb_ttl_msg        db "TTL=", 0
cb_sum_hdr        db 10, "--- [ CALLBACK-PING REPORT ] ---", 10, 0
cb_sum_total      db "Total callbacks : ", 0
cb_sum_silent     db "Silent drops    : ", 0
cb_sum_standard   db "Standard resp   : ", 0
cb_sum_responsive db "Protocol resp   : ", 0
cb_sum_delayed    db "Delayed resp    : ", 0
cb_sum_os_hdr     db "OS breakdown    :", 10, 0
cb_sum_linux      db "  Linux         : ", 0
cb_sum_windows    db "  Windows       : ", 0
cb_sum_macos      db "  macOS         : ", 0
cb_sum_device     db "  Device        : ", 0
cb_sum_unknown    db "  Unknown       : ", 0

align 4
cb_dns_payload:
    db 0xCB, 0x4B
    db 0x01, 0x00
    db 0x00, 0x01
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 8,'c','a','l','l','b','a','c','k'
    db 5,'l','o','c','a','l', 0
    db 0x00, 0x01
    db 0x00, 0x01
cb_dns_len equ $ - cb_dns_payload

cb_ntp_payload:
    db 0x1B
    times 47 db 0x00
cb_ntp_len equ $ - cb_ntp_payload

wizard_hdr      db 10, "  NetroX-ASM Wizard", 10
                db "  ---------------------", 10
wizard_hdr_len  equ $-wizard_hdr

wiz_q_target    db "  [1] Target IP address: "
wiz_q_target_len equ $-wiz_q_target

wiz_q_ports     db "  [2] Port range (e.g. 1-1000, 80, or - for all): "
wiz_q_ports_len equ $-wiz_q_ports

wiz_q_mode      db "  [3] Scan mode:", 10
                db "      syn    - TCP SYN (default, fast, reliable)", 10
                db "      ack    - TCP ACK (firewall mapping)", 10
                db "      fin    - TCP FIN (bypass some filters)", 10
                db "      null   - No flags (bypass some filters)", 10
                db "      xmas   - FIN+PSH+URG (bypass some filters)", 10
                db "      udp    - UDP datagram scan", 10
                db "      ping   - ICMP echo host discovery", 10
                db "  Choice [syn]: "
wiz_q_mode_len  equ $-wiz_q_mode

wiz_q_rate      db "  [4] Rate limit in packets/sec (0 = unlimited): "
wiz_q_rate_len  equ $-wiz_q_rate

wiz_q_os        db "  [5] Enable OS fingerprinting? (y/n) [n]: "
wiz_q_os_len    equ $-wiz_q_os

wiz_q_bench     db "  [6] Show benchmark stats after scan? (y/n) [n]: "
wiz_q_bench_len equ $-wiz_q_bench

wiz_q_stab      db "  [7] Enable adaptive rate stabilizer? (y/n) [n]: "
wiz_q_stab_len  equ $-wiz_q_stab

wiz_summary_hdr db 10, "  --- Scan Summary ---", 10
wiz_summary_hdr_len equ $-wiz_summary_hdr

wiz_sum_target  db "  Target  : "
wiz_sum_target_len equ $-wiz_sum_target

wiz_sum_ports   db "  Ports   : "
wiz_sum_ports_len equ $-wiz_sum_ports

wiz_sum_mode    db "  Mode    : "
wiz_sum_mode_len equ $-wiz_sum_mode

wiz_sum_rate    db "  Rate    : "
wiz_sum_rate_len equ $-wiz_sum_rate

wiz_sum_flags   db "  Flags   : "
wiz_sum_flags_len equ $-wiz_sum_flags

wiz_confirm     db 10, "  Start scan? (y/n): "
wiz_confirm_len equ $-wiz_confirm

wiz_abort       db "  Aborted.", 10
wiz_abort_len   equ $-wiz_abort

wiz_starting    db "  Starting...", 10, 10
wiz_starting_len equ $-wiz_starting

wiz_unlim       db "unlimited"
wiz_unlim_len   equ $-wiz_unlim

wiz_flag_os     db "os "
wiz_flag_os_len equ $-wiz_flag_os

wiz_flag_bench  db "bench "
wiz_flag_bench_len equ $-wiz_flag_bench

wiz_flag_stab   db "stabilize "
wiz_flag_stab_len equ $-wiz_flag_stab

wiz_flag_none   db "none"
wiz_flag_none_len equ $-wiz_flag_none

wiz_dash        db " - "
wiz_dash_len    equ $-wiz_dash

; Mode name strings for summary display
wiz_mode_syn    db "syn",    0
wiz_mode_ack    db "ack",    0
wiz_mode_fin    db "fin",    0
wiz_mode_null   db "null",   0
wiz_mode_xmas   db "xmas",   0
wiz_mode_window db "window", 0
wiz_mode_maimon db "maimon", 0
wiz_mode_udp    db "udp",    0
wiz_mode_ping   db "ping",   0

; Pointer table indexed by SCAN_xxx constant (1-based)
wiz_mode_ptrs   dq 0
                dq wiz_mode_syn
                dq wiz_mode_ack
                dq wiz_mode_fin
                dq wiz_mode_null
                dq wiz_mode_xmas
                dq wiz_mode_window
                dq wiz_mode_maimon
                dq wiz_mode_udp
                dq wiz_mode_ping

; Target IP string buffer for summary display
wiz_target_str  db "               ", 0  ; 16 bytes, filled at runtime

disc_up_msg     db " UP   TTL=", 0
disc_up_len     equ $-disc_up_msg
disc_rtt_msg    db " RTT=", 0
disc_rtt_len    equ $-disc_rtt_msg
disc_ms_msg     db "ms", 13, 10, 0
disc_ms_len     equ $-disc_ms_msg
disc_down_msg   db " DOWN", 13, 10, 0
disc_down_len   equ $-disc_down_msg
disc_hdr_msg    db "--- Host Discovery ---", 13, 10, 0
disc_hdr_len    equ $-disc_hdr_msg

timing_t0_rate  dd 0
timing_t1_rate  dd 3
timing_t2_rate  dd 10
timing_t3_rate  dd 0
timing_t4_rate  dd 100000
timing_t5_rate  dd 0

json_open_brace   db "{", 13, 10
json_open_len     equ $-json_open_brace
json_close_brace  db "}", 13, 10
json_close_len    equ $-json_close_brace
json_target_key   db "  \"target\": \""
json_target_klen  equ $-json_target_key
json_target_end   db "\"", 13, 10
json_target_elen  equ $-json_target_end
json_ports_key    db "  \"ports\": [", 13, 10
json_ports_klen   equ $-json_ports_key
json_port_open    db "    {\"port\": "
json_port_oplen   equ $-json_port_open
json_state_open   db ", \"state\": \"open\""
json_state_oplen  equ $-json_state_open
json_state_closed db ", \"state\": \"closed\""
json_state_clen   equ $-json_state_closed
json_state_filt   db ", \"state\": \"filtered\""
json_state_flen   equ $-json_state_filt
json_ttl_key      db ", \"ttl\": "
json_ttl_klen     equ $-json_ttl_key
json_close_obj    db "},"
json_close_olen   equ $-json_close_obj
json_ports_end    db "  ]", 13, 10
json_ports_elen   equ $-json_ports_end
json_comma_nl     db ",", 13, 10
json_comma_nl_len equ $-json_comma_nl

csv_header      db "ip,port,state,ttl,rtt_us,os", 13, 10
csv_header_len  equ $-csv_header
csv_open_str    db ",open,"
csv_open_len    equ $-csv_open_str
csv_closed_str  db ",closed,"
csv_closed_len  equ $-csv_closed_str
csv_filt_str    db ",filtered,"
csv_filt_len    equ $-csv_filt_str
csv_comma       db ","
csv_comma_len   equ $-csv_comma

closed_msg      db " CLOSED", 13, 10
closed_len      equ $-closed_msg
filtered_msg    db " FILTERED", 13, 10
filtered_len    equ $-filtered_msg
open_ttl_msg    db " OPEN TTL="
open_ttl_len    equ $-open_ttl_msg
open_win_msg    db " WIN="
open_win_len    equ $-open_win_msg
newline_msg     db 13, 10
newline_len     equ $-newline_msg
space_msg       db " "
space_len       equ $-space_msg
error_msg       db "ERROR", 13, 10
error_len       equ $-error_msg

open_count_msg  db "OPEN COUNT: "
open_count_len  equ $-open_count_msg
open_ports_msg  db "OPEN PORTS: "
open_ports_len  equ $-open_ports_msg
none_msg        db "none"
none_len        equ $-none_msg

os_prefix_msg   db " OS="
os_prefix_len   equ $-os_prefix_msg

bench_hdr_msg   db 13, 10, "--- NETX-ASM BENCHMARK ---", 13, 10
bench_hdr_len   equ $-bench_hdr_msg
bench_ports_msg db "Ports scanned : "
bench_ports_len equ $-bench_ports_msg
bench_open_msg  db "Open found    : "
bench_open_len  equ $-bench_open_msg
bench_time_msg  db "Elapsed (ms)  : "
bench_time_len  equ $-bench_time_msg
bench_end_msg   db "--------------------------", 13, 10
bench_end_len   equ $-bench_end_msg

os_str_0    db "Linux-5.x/6.x", 0
os_str_1    db "Linux-3.x/4.x", 0
os_str_2    db "Windows-10/11", 0
os_str_3    db "Windows-7/8",   0
os_str_4    db "macOS/BSD",      0
os_str_5    db "Network-Device", 0
os_str_6    db "Unknown",        0
os_str_ptrs dq os_str_0, os_str_1, os_str_2, os_str_3
            dq os_str_4, os_str_5, os_str_6

hdrincl     dd 1
timeout_ms  dd 1000

src_port    dw 40000
start_port  dw 1
end_port    dw 1000
src_port_be dw 0
dst_port_be dw 0
align 16
pkt_template_0  db 0x45,0x00,0x00,0x28,0x00,0x00,0x40,0x00
                db 0x40,0x06,0x00,0x00,0x00,0x00,0x00,0x00
pkt_template_1  db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
pkt_template_2  db 0x00,0x00,0x00,0x00,0x50,0x02,0xFF,0xFF
                db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
align 8
flag_table      db 0x02,0x02,0x10,0x01,0x00,0x29,0x10,0x11,0x00,0x00

; ---------------------------------------------------------------------------
; .rodata
; ---------------------------------------------------------------------------
SECTION .rodata

; Top 100 most commonly open TCP ports (frequency-ranked)
top_100_ports:
    dw 80,  23,  443, 21,  22,  25,  3389, 110, 445, 139
    dw 143, 53,  135, 3306,8080,1723,111,  995, 993, 5900
    dw 1025,587, 8888,199, 1720,465, 548,  113, 81,  6001
    dw 10000,514,5432,1433,3306,1521,49152,514, 8443,5000
    dw 5901, 102,10001,8008,2082,8443,4443, 7547,623, 161
    dw 6443, 9100,631, 9000,3000,8888,8161, 9090,7001,8009
    dw 4848, 4786,32764,2375,2376,9200,5984, 11211,6379,27017
    dw 2181, 9092,8500,5672,4369,15672,61616,9300,7474,7473
    dw 1194, 500, 1701,4500,1900,5353,17185, 5683,49153,49154
    dw 49155,49156,49157,49158,49159,49160,49161,49162,49163,49164
top_100_count equ 100

; Top 1000 — first 100 same as above, add 900 more common ports
top_1000_ports:
    ; include top_100_ports then continue with:
    dw 7,   9,   13,  17,  19,  37,  79,  88,  106, 109
    dw 115, 118, 119, 123, 137, 138, 139, 143, 179, 194
    dw 220, 389, 427, 443, 444, 458, 464, 465, 497, 500
    dw 512, 513, 515, 520, 548, 554, 587, 593, 601, 631
    dw 636, 646, 787, 808, 873, 902, 903, 993, 995, 1000
    dw 1022,1023,1024,1025,1026,1027,1028,1029,1030,1720
    ; ... extend to 1000 entries total
top_1000_count equ 1000

; ---------------------------------------------------------------------------
; .bss
; ---------------------------------------------------------------------------
SECTION .bss

wsa_data        resb 512
packet_buf      resb 60
recv_buf        resb 4096
out_buf         resb 16
output_buf      resb OUTPUT_BUF_SIZE
output_pos      resq 1
cmd_buf         resb 1024

sockaddr_dst    resb 16
sockaddr_tmp    resb 16
sockaddr_local  resb 16
addrlen         resd 1

sock_fd         resq 1
stdout_handle   resq 1
stdin_handle    resq 1
bytes_written   resd 1
bytes_read      resd 1

target_ip       resd 1
source_ip       resd 1
last_ttl        resb 1
last_win        resw 1

result_map      resb 8192
open_count      resd 1

engine_id       resb 1
scan_mode       resb 1

rate_value      resd 1
rate_cycles     resq 1
rate_min_cycles resq 1
rate_max_cycles resq 1
rate_enabled    resb 1
last_send_tsc   resq 1
tsc_hz          resq 1
qpc_freq        resq 1
qpc_start       resq 1
qpc_end         resq 1
tsc_start       resq 1

stab_enabled    resb 1
stab_sent       resd 1
stab_recv       resd 1
stab_timeout    resd 1
bench_enabled   resb 1
os_enabled      resb 1
bench_start_tsc resq 1
bench_end_tsc   resq 1
os_result_idx   resb 1
intel_rtt_table     resd 65535
intel_ipid_ring     resw 6
intel_ipid_idx      resb 1
intel_lb_ttl        resb 5
intel_lb_win        resw 5
intel_lb_ts         resd 5
intel_lb_opthash    resd 5
intel_lb_idx        resb 1
intel_rtt_before    resq 1
intel_fp_ttl        resb 1
intel_fp_win        resw 1
intel_fp_mss        resw 1
intel_fp_wscale     resb 1
intel_fp_sack       resb 1
intel_fp_ts         resb 1
intel_fp_ts_val     resd 1
intel_fp_df         resb 1
intel_fp_ipid_class resb 1
intel_fp_opthash    resd 1
intel_fp_scores     resb 7
intel_fp_best_idx   resb 1
intel_fp_best_score resb 1
intel_svc_id        resb 1
intel_svc_name      resb 16
intel_banner        resb 64
intel_banner_len    resw 1
intel_port_cur      resw 1
align 64
packet_buf_aligned  resb 64
align 64
pkt_ring            resb 1024
ring_send_idx       resb 1
ring_build_idx      resb 1
batch_counter       resb 1
xorshift_state      resq 1
input_buf           resb 256
prompt_mode         resb 1
wiz_any_flag        resb 1
blackrock_key_0     resq 1
blackrock_key_1     resq 1
blackrock_key_2     resq 1
blackrock_key_3     resq 1
blackrock_key_4     resq 1
blackrock_key_5     resq 1
host_up_map         resb 1
disc_enabled        resb 1
disc_mode           resb 1
port_list_buf       resw 256
port_list_count     resw 1
port_list_mode      resb 1
top_ports_n         resw 1
top_ports_mode      resb 1
top_ports_ptr       resq 1
timing_level        resb 1
scan_delay          resd 1
retry_max           resb 1
retry_cur           resb 1
json_mode           resb 1
json_first_port     resb 1
csv_mode            resb 1
output_fd           resq 1
output_filename     resb 256

; SAR engine state
sar_enabled         resb 1
sar_baseline_ns     resq 1
sar_baseline_samples resq 5
sar_synced          resb 1
sar_synaptic_limit  resw 1
sar_class           resb 1
sar_delta_history   resw 8
sar_delta_hist_idx  resb 1
sar_timeout_streak  resb 1
sar_rtt_samples     resq 3
sar_rtt_idx         resb 1
sar_t_send          resq 1
sar_t_recv          resq 1
sar_chameleon_ns    resq 1
sar_synthetic_ns    resq 1
sar_delta_display   resb 1

sar_count_none      resd 1
sar_count_acl       resd 1
sar_count_stateful  resd 1
sar_count_dpi       resd 1
sar_count_ai        resd 1
sar_count_proxy     resd 1
sar_count_syncs     resd 1
sar_count_total     resd 1
sar_results         resb 65535 * 16
waveform_buf        resb 80
waveform_col        resb 1

; KIS engine state
kis_enabled          resb 1
kis_fuse_blown       resb 1
kis_fuse_reason      resb 1
kis_ambient_ns       resq 1
kis_ambient_ttl      resb 1
kis_ambient_samples  resq 8
kis_jitter_baseline  resq 1
kis_recheck_counter  resb 1
kis_timeout_streak   resb 1
kis_baseline_orig    resq 1
kis_closed_ref_ns    resq 1
kis_t_send           resq 1
kis_t_recv           resq 1
kis_svc_id           resw 1
kis_confidence       resb 1
kis_probe_samples    resq 5
kis_port_impedance   resq 1
kis_port_jitter      resq 1

kis_count_closed     resd 1
kis_count_filtered   resd 1
kis_count_open       resd 1
kis_count_heavy      resd 1
kis_count_virt       resd 1
kis_count_unknown    resd 1
kis_count_total      resd 1

kis_results          resb 65535 * 24
kis_heatmap_buf      resb 65535

; Phantom engine state
phantom_enabled           resb 1
phantom_tev_threshold     resb 1
phantom_idle_rtt          resq 1
phantom_listen_secs       resb 1
phantom_burst_window_ns   resq 1
phantom_jitter_min_us     resd 1
phantom_jitter_max_us     resd 1
phantom_last_ambient_tsc  resq 1
phantom_bytes_sent        resq 1
phantom_pkts_sent         resd 1
phantom_t_send            resq 1
phantom_t_recv            resq 1
phantom_probe_rtt         resq 1
phantom_port_state        resb 1
passive_open_map          resb 8192
passive_port_count        resd 1

tev_history               resw 8
tev_history_idx           resb 1
tev_consecutive_to        resb 1
tev_triggered             resb 1

phantom_count_passive     resd 1
phantom_count_open        resd 1
phantom_count_closed      resd 1
phantom_count_filtered    resd 1
phantom_count_tev         resd 1
phantom_count_total       resd 1

; Callback engine state
cb_enabled            resb 1
cb_secondary_enabled  resb 1
cb_proto              resb 1
cb_response_timeout   resd 1
cb_t_send             resq 1
cb_t_recv             resq 1
cb_latency_ns         resq 1
cb_class              resb 1
cb_src_ip             resd 1
cb_src_port           resw 1
cb_trigger_proto      resb 1

cb_queue              resb 128
cb_queue_head         resb 1
cb_queue_tail         resb 1
cb_queue_count        resb 1
cb_subnet_seen        resb 8192

cb_count_total        resd 1
cb_count_silent       resd 1
cb_count_standard     resd 1
cb_count_responsive   resd 1
cb_count_delayed      resd 1
cb_count_linux        resd 1
cb_count_windows      resd 1
cb_count_macos        resd 1
cb_count_device       resd 1
cb_count_unknown_os   resd 1

; Cookie/CIDR compatibility
scan_seed     resq 1
local_ip      resd 1
cidr_mode     resb 1
current_scan_ip resd 1
ip_ranges         resb MAX_IP_RANGES * IP_RANGE_ENTRY
ip_range_count    resd 1
total_ip_count    resq 1
total_index_max   resq 1

resume_index      resq 1
resume_filename   resb 256
resume_enabled    resb 1
resume_flag       resb 1
resume_fd         resq 1

config_filename   resb 256
config_enabled    resb 1
config_buf        resb 4096

wait_secs         resb 1
banners_mode      resb 1
echo_mode         resb 1
random_host_count resd 1
version_enabled   resb 1
quiet_mode        resb 1

; ===========================================================================
; NetroX-ASM  |  Windows x86_64  |  Part 2 of 4: _start, args, init, scan loop
; ===========================================================================

SECTION .text

_start:
    mov qword [sock_fd], INVALID_SOCKET
    sub rsp, 40
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    add rsp, 40
    mov [stdout_handle], rax
    sub rsp, 40
    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    add rsp, 40
    mov [stdin_handle], rax

    ; WSAStartup
    sub rsp, 40
    mov ecx, 0x0202
    lea rdx, [wsa_data]
    call WSAStartup
    add rsp, 40
    test eax, eax
    jne .error

    ; Copy command line to cmd_buf
    sub rsp, 40
    call GetCommandLineA
    add rsp, 40
    mov rsi, rax
    lea rdi, [cmd_buf]
.copy_cmd:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    test al, al
    jnz .copy_cmd

    ; Skip program name token
    lea rdi, [cmd_buf]
    call next_token
    mov rdi, rdx

    ; First real arg
    call next_token
    test rax, rax
    jz .usage
    mov rsi, rax

    mov rdi, rsi
    call is_about_mode
    test eax, eax
    jnz .about_entry
    mov rdi, rsi
    call is_wizard_mode
    test eax, eax
    jnz .wizard_entry
    mov rdi, rsi
    call parse_ip
    test eax, eax
    jz .usage
    mov [target_ip], eax
    mov [current_scan_ip], eax
    lea rsi, [rsi]
    lea rdi, [wiz_target_str]
    mov ecx, 15
.copy_target_ip:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .target_ip_copied
    inc rsi
    inc rdi
    loop .copy_target_ip
    mov byte [rdi], 0
.target_ip_copied:

    mov rdi, rdx

.arg_loop:
    call next_token
    test rax, rax
    jz .ports_ready
    mov rsi, rax
    cmp byte [rsi], '-'
    jne .arg_next

    ; -T<0-5>
    cmp byte [rsi+1], 'T'
    jne .check_p
    mov al, [rsi+2]
    cmp al, '0'
    jb .check_p
    cmp al, '5'
    ja .check_p
    sub al, '0'
    mov [timing_level], al
    cmp al, 0
    jne .t1
    mov dword [rate_value], 0
    mov dword [scan_delay], 15000
    jmp .arg_next
.t1:
    cmp al, 1
    jne .t2
    mov dword [rate_value], 3
    jmp .arg_next
.t2:
    cmp al, 2
    jne .t3
    mov dword [rate_value], 10
    jmp .arg_next
.t3:
    cmp al, 3
    jne .t4
    mov dword [rate_value], 0
    jmp .arg_next
.t4:
    cmp al, 4
    jne .t5
    mov dword [rate_value], 100000
    mov byte [stab_enabled], 0
    jmp .arg_next
.t5:
    mov dword [rate_value], 0
    mov byte [stab_enabled], 0
    jmp .arg_next

.check_p:
    ; -p port|range|-
    cmp byte [rsi+1], 'p'
    jne .check_rate
    cmp byte [rsi+2], 0
    jne .check_rate
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    ; comma list?
    push rdi
    mov rsi, rdi
.plist_scan:
    mov al, [rsi]
    test al, al
    jz .plist_no
    cmp al, ','
    je .plist_yes
    inc rsi
    jmp .plist_scan
.plist_yes:
    pop rdi
    call parse_port_list
    cmp word [port_list_count], 0
    je .usage
    mov byte [port_list_mode], 1
    jmp .arg_next
.plist_no:
    pop rdi
    cmp byte [rdi], '-'
    jne .parse_range
    cmp byte [rdi+1], 0
    jne .parse_range
    mov word [start_port], 1
    mov word [end_port], 65535
    jmp .arg_next

.parse_range:
    call parse_port_range
    test ax, ax
    jz .usage
    mov [start_port], ax
    mov [end_port], dx
    jmp .arg_next

.check_rate:
    cmp byte [rsi+1], '-'
    jne .check_scan
    cmp dword [rsi+2], 'rate'
    jne .check_scan
    cmp byte [rsi+6], 0
    jne .check_scan
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    call parse_u32
    test eax, eax
    jz .usage
    mov [rate_value], eax
    jmp .arg_next

.check_scan:
    cmp byte [rsi+1], '-'
    jne .check_discovery
    cmp dword [rsi+2], 'scan'
    jne .check_discovery
    cmp byte [rsi+6], 0
    jne .check_discovery
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    call parse_scan_mode
    test al, al
    jz .usage
    mov [scan_mode], al
    jmp .arg_next

.check_discovery:
    ; --discovery MODE
    cmp byte [rsi+1], '-'
    jne .check_top_ports
    cmp dword [rsi+2], 'disc'
    jne .check_top_ports
    cmp dword [rsi+6], 'over'
    jne .check_top_ports
    cmp byte [rsi+10], 'y'
    jne .check_top_ports
    cmp byte [rsi+11], 0
    jne .check_top_ports
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    mov byte [disc_enabled], 1
    mov byte [disc_mode], 1
    mov al, [rdi]
    cmp al, 's'
    jne .disc_ack
    cmp byte [rdi+1], 'y'
    jne .disc_ack
    cmp byte [rdi+2], 'n'
    jne .disc_ack
    cmp byte [rdi+3], 0
    jne .disc_ack
    mov byte [disc_mode], 2
    jmp .arg_next
.disc_ack:
    cmp al, 'a'
    jne .disc_udp
    cmp byte [rdi+1], 'c'
    jne .disc_udp
    cmp byte [rdi+2], 'k'
    jne .disc_udp
    cmp byte [rdi+3], 0
    jne .disc_udp
    mov byte [disc_mode], 3
    jmp .arg_next
.disc_udp:
    cmp al, 'u'
    jne .disc_ping
    cmp byte [rdi+1], 'd'
    jne .disc_ping
    cmp byte [rdi+2], 'p'
    jne .disc_ping
    cmp byte [rdi+3], 0
    jne .disc_ping
    mov byte [disc_mode], 4
    jmp .arg_next
.disc_ping:
    jmp .arg_next

.check_top_ports:
    ; --top-ports N
    cmp byte [rsi+1], '-'
    jne .check_json
    cmp dword [rsi+2], 'top-'
    jne .check_json
    cmp dword [rsi+6], 'port'
    jne .check_json
    cmp byte [rsi+10], 's'
    jne .check_json
    cmp byte [rsi+11], 0
    jne .check_json
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    call parse_u32
    test eax, eax
    jz .usage
    mov [top_ports_n], ax
    cmp eax, 100
    jbe .top100
    cmp eax, 1000
    jbe .top1000
    jmp .usage
.top100:
    lea rax, [top_100_ports]
    mov [top_ports_ptr], rax
    mov byte [top_ports_mode], 1
    jmp .arg_next
.top1000:
    lea rax, [top_1000_ports]
    mov [top_ports_ptr], rax
    mov byte [top_ports_mode], 1
    jmp .arg_next

.check_json:
    ; --json
    cmp byte [rsi+1], '-'
    jne .check_csv
    cmp dword [rsi+2], 'json'
    jne .check_csv
    cmp byte [rsi+6], 0
    jne .check_csv
    mov byte [json_mode], 1
    mov byte [json_first_port], 1
    jmp .arg_next

.check_csv:
    ; --csv
    cmp byte [rsi+1], '-'
    jne .check_output
    cmp dword [rsi+2], 'csv'
    jne .check_output
    cmp byte [rsi+5], 0
    jne .check_output
    mov byte [csv_mode], 1
    jmp .arg_next

.check_output:
    ; --output FILE
    cmp byte [rsi+1], '-'
    jne .check_retries
    cmp dword [rsi+2], 'outp'
    jne .check_retries
    cmp dword [rsi+6], 'ut'
    jne .check_retries
    cmp byte [rsi+8], 0
    jne .check_retries
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rsi, rax
    lea rdi, [output_filename]
    mov ecx, 255
.out_copy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .out_open
    inc rsi
    inc rdi
    loop .out_copy
    mov byte [rdi], 0
.out_open:
    ; CreateFileA(filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
    sub rsp, 56
    lea rcx, [output_filename]
    mov edx, 0x40000000
    xor r8d, r8d
    xor r9d, r9d
    mov qword [rsp+32], 2
    mov qword [rsp+40], 0x80
    mov qword [rsp+48], 0
    call CreateFileA
    add rsp, 56
    mov [output_fd], rax
    jmp .arg_next

.check_retries:
    ; --retries N
    cmp byte [rsi+1], '-'
    jne .check_bench
    cmp dword [rsi+2], 'retr'
    jne .check_bench
    cmp dword [rsi+6], 'ies'
    jne .check_bench
    cmp byte [rsi+9], 0
    jne .check_bench
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
    call parse_u32
    cmp eax, 6
    jbe .retry_set
    mov eax, 6
.retry_set:
    mov [retry_max], al
    jmp .arg_next

.check_bench:
    cmp byte [rsi+1], '-'
    jne .check_os
    cmp dword [rsi+2], 'benc'
    jne .check_os
    cmp word  [rsi+6], 'h'
    jne .check_os
    cmp byte  [rsi+7], 0
    jne .check_os
    mov byte [bench_enabled], 1
    jmp .arg_next

.check_os:
    cmp byte [rsi+1], '-'
    jne .check_stabilize
    cmp word  [rsi+2], 'os'
    jne .check_stabilize
    cmp byte  [rsi+4], 0
    jne .check_stabilize
    mov byte [os_enabled], 1
    jmp .arg_next

.check_stabilize:
    cmp byte [rsi+1], '-'
    jne .arg_next
    cmp dword [rsi+2],  'stab'
    jne .arg_next
    cmp dword [rsi+6],  'iliz'
    jne .arg_next
    cmp word  [rsi+10], 'e'
    jne .arg_next
    cmp byte  [rsi+11], 0
    jne .arg_next
    mov byte [stab_enabled], 1

.arg_next:
    mov rdi, rdx
    jmp .arg_loop

; -------------------------------------------------------------------
; All args parsed
; -------------------------------------------------------------------
.ports_ready:
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax

    cmp byte [scan_mode], 0
    jne .scan_mode_set
    mov byte [scan_mode], SCAN_SYN
.scan_mode_set:
    mov byte [engine_id], ENGINE_SYN

    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write

    call get_local_ip
    test eax, eax
    jnz .error
    mov eax, [source_ip]
    mov [local_ip], eax

    call init_rate
    call blackrock_init
    call intel_init
    call cookie_init
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [xorshift_state], rax
    mov byte [batch_counter], 0

    ; Bench start
    cmp byte [bench_enabled], 0
    je .after_bench_start
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [bench_start_tsc], rax
.after_bench_start:

    ; Open raw socket
    sub rsp, 40
    mov ecx, AF_INET
    mov edx, SOCK_RAW
    mov r8d, IPPROTO_TCP
    call socket
    add rsp, 40
    cmp rax, INVALID_SOCKET
    je .error
    mov [sock_fd], rax

    sub rsp, 40
    mov rcx, [sock_fd]
    mov edx, IPPROTO_IP
    mov r8d, IP_HDRINCL
    lea r9, [hdrincl]
    mov dword [rsp+32], 4
    call setsockopt
    add rsp, 40
    test eax, eax
    jne .error

    sub rsp, 40
    mov rcx, [sock_fd]
    mov edx, SOL_SOCKET
    mov r8d, SO_RCVTIMEO
    lea r9, [timeout_ms]
    mov dword [rsp+32], 4
    call setsockopt
    add rsp, 40

    call init_packet_template

    cmp byte [json_mode], 0
    je .skip_json_header
    call json_print_header
.skip_json_header:
    cmp byte [csv_mode], 0
    je .skip_csv_header
    lea rsi, [csv_header]
    mov edx, csv_header_len
    call buf_write
.skip_csv_header:

    cmp byte [disc_enabled], 0
    je .skip_discovery
    cmp byte [disc_mode], 1
    jne .skip_discovery
    call icmp_host_probe
    cmp byte [host_up_map], 0
    je .scan_done
.skip_discovery:

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    xor ebx, ebx
    xor r13, r13
    cmp byte [port_list_mode], 0
    je .check_top_ports_mode
    lea r13, [port_list_buf]
    movzx r15d, word [port_list_count]
    jmp .scan_ready
.check_top_ports_mode:
    cmp byte [top_ports_mode], 0
    je .scan_ready
    mov r13, [top_ports_ptr]
    movzx r15d, word [top_ports_n]
.scan_ready:

; -------------------------------------------------------------------
; Scan loop
; -------------------------------------------------------------------
.scan_loop:
    test r13, r13
    jz .range_check
    cmp rbx, r15
    ja .scan_done
    mov rdi, rbx
    mov rsi, r15
    call blackrock_permute
    movzx ecx, word [r13 + rax*2]
    jmp .port_ready
.range_check:
    cmp ecx, r15d
    ja .scan_done
.port_ready:
    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    call build_packet
.retry_send:
    call intel_rtt_start
    call intelligence_gate

    ; TCP packet length
    mov edx, 40
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [packet_buf]
    ; rdx already set above - but sendto expects: rcx=sock,rdx=buf,r8=len,...
    ; We need to reorganise: r8d = len, rdx=buf
    mov r8d, edx                        ; len
    lea rdx, [packet_buf]               ; buf (re-set)
    xor r9d, r9d
    lea rax, [sockaddr_dst]
    mov [rsp+32], rax
    mov qword [rsp+40], 16
    call sendto
    add rsp, 56
    cmp eax, SOCKET_ERROR
    je .error
    cmp byte [stab_enabled], 0
    je .after_sent
    inc dword [stab_sent]
.after_sent:

    ; recvfrom (blocking, SO_RCVTIMEO = 1s)
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [recv_buf]
    mov r8d, 4096
    xor r9d, r9d
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    call recvfrom
    add rsp, 56
    cmp eax, SOCKET_ERROR
    je .report_filtered

    lea rsi, [recv_buf]

    ; TCP response decode
    mov al, [rsi+9]
    cmp al, 6
    jne .report_filtered
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .report_filtered
    mov al, [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]
    mov ax, [rdx]
    cmp ax, [dst_port_be]
    jne .report_filtered
    mov ax, [rdx+2]
    cmp ax, [src_port_be]
    jne .report_filtered
    mov al, [rsi+8]
    mov [last_ttl], al
    mov ax, [rdx+14]
    xchg al, ah
    mov [last_win], ax
    call intel_rtt_record
    cmp byte [os_enabled], 0
    je .classify_flags
    call intel_analyze

.classify_flags:
    mov al, [rdx+13]
    mov bl, al
    mov dl, [scan_mode]
    cmp dl, SCAN_SYN
    je .classify_syn
    cmp dl, SCAN_ACK
    je .classify_ack
    cmp dl, SCAN_WINDOW
    je .classify_ack
    test bl, 0x04
    jnz .report_closed
    jmp .report_filtered

.classify_ack:
    test bl, 0x04
    jnz .report_open
    jmp .report_filtered

.classify_syn:
    and bl, 0x12
    cmp bl, 0x12
    je .report_open
    test al, 0x04
    jnz .report_closed
    jmp .report_filtered

.report_open:
    mov byte [retry_cur], 0
    mov al, 1
    call json_print_port
    mov al, 1
    call csv_print_port
    call record_open
    cmp byte [stab_enabled], 0
    je .open_no_stab
    inc dword [stab_recv]
.open_no_stab:
    mov ax, cx
    call write_open_intel
    cmp byte [os_enabled], 0
    je .skip_intel_print
    mov word [intel_port_cur], cx
    call intel_print_record
    .skip_intel_print:
    jmp .next_port

.report_closed:
    mov byte [retry_cur], 0
    mov al, 2
    call json_print_port
    mov al, 2
    call csv_print_port
    cmp byte [stab_enabled], 0
    je .closed_no_stab
    inc dword [stab_recv]
.closed_no_stab:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    jmp .next_port

.report_filtered:
    mov al, [retry_cur]
    cmp al, [retry_max]
    jb .retry_again
    mov byte [retry_cur], 0
    mov al, 3
    call json_print_port
    mov al, 3
    call csv_print_port
    cmp byte [stab_enabled], 0
    je .filtered_no_stab
    inc dword [stab_timeout]
.filtered_no_stab:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    jmp .next_port

.retry_again:
    inc byte [retry_cur]
    jmp .retry_send

.next_port:
    call stabilize_step
    test r13, r13
    jz .inc_range
    inc rbx
    jmp .scan_loop
.inc_range:
    inc ecx
    jmp .scan_loop

.scan_done:
    cmp byte [bench_enabled], 0
    je .skip_bench_end
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [bench_end_tsc], rax
.skip_bench_end:
    call write_summary
    cmp byte [json_mode], 0
    je .skip_json_footer
    call json_print_footer
.skip_json_footer:
    cmp byte [os_enabled], 0
    je .skip_rtt_map
    call intel_print_rtt_map
    .skip_rtt_map:
    cmp byte [bench_enabled], 0
    je .skip_bench_print
    call write_bench
.skip_bench_print:
    jmp .exit

.wizard_entry:
    mov byte [prompt_mode], 1
    call wizard_flow
    test eax, eax
    jnz .prompt_fail
    jmp .ports_ready

.prompt_fail:
    jmp .exit

.about_entry:
    call print_about
    jmp .exit

.usage:
    lea rsi, [usage_msg]
    mov edx, usage_len
    call write_stdout
    jmp .exit

.error:
    call flush_output
    lea rsi, [error_msg]
    mov edx, error_len
    call write_stdout

.exit:
    call flush_output
    mov rax, [output_fd]
    test rax, rax
    jz .exit_no_out
    sub rsp, 40
    mov rcx, rax
    call CloseHandle
    add rsp, 40
.exit_no_out:
    mov rax, [sock_fd]
    cmp rax, INVALID_SOCKET
    je .cleanup
    sub rsp, 40
    mov rcx, rax
    call closesocket
    add rsp, 40
.cleanup:
    sub rsp, 40
    call WSACleanup
    add rsp, 40
    sub rsp, 40
    xor ecx, ecx
    call ExitProcess

; ===========================================================================
; NetroX-ASM  |  Windows x86_64  |  Part 3 of 4: Output, OS FP, summary, bench
; ===========================================================================

; -------------------------------------------------------------------
; write_stdout  rsi=buf, edx=len
; Direct WriteFile to console stdout
; -------------------------------------------------------------------
write_stdout:
    sub rsp, 40
    mov rcx, [stdout_handle]
    mov r8d, edx
    mov rdx, rsi
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    add rsp, 40
    ret

; -------------------------------------------------------------------
; buf_write  rsi=src, edx=len
; Buffered write (flushed at threshold)
; -------------------------------------------------------------------
buf_write:
    mov r8, rsi
    mov r9d, edx
    mov rax, [output_pos]
    mov rcx, rax
    add rcx, r9
    cmp rcx, OUTPUT_BUF_SIZE
    ja .flush_first
    cmp rcx, OUTPUT_FLUSH_THRESHOLD
    jae .flush_first
.write_inner:
    lea rdi, [output_buf+rax]
    mov rsi, r8
    mov rdx, r9
    mov rcx, rdx
    rep movsb
    add rax, r9
    mov [output_pos], rax
    ret
.flush_first:
    call flush_output
    mov rax, [output_pos]
    jmp .write_inner

flush_output:
    mov rax, [output_pos]
    test rax, rax
    jz .done
    lea rsi, [output_buf]
    mov edx, eax
    call write_stdout
    mov rax, [output_fd]
    test rax, rax
    jz .clear
    sub rsp, 40
    mov rcx, rax
    lea rdx, [output_buf]
    mov r8d, edx
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    add rsp, 40
.clear:
    mov qword [output_pos], 0
.done:
    ret

; -------------------------------------------------------------------
; append_u16  ax=value
; -------------------------------------------------------------------
append_u16:
    movzx eax, ax
    lea rsi, [out_buf+6]
    xor rcx, rcx
.digits:
    mov r8d, eax
    mov r11d, 0xCCCCCCCD
    mul r11d
    mov eax, edx
    shr eax, 3
    lea edx, [eax*4 + eax]
    add edx, edx
    sub r8d, edx
    add r8b, '0'
    dec rsi
    mov [rsi], r8b
    inc rcx
    test eax, eax
    jnz .digits
    mov edx, ecx
    call buf_write
    ret

; -------------------------------------------------------------------
; write_result  ax=port, r9=msg_ptr, r10d=msg_len
; -------------------------------------------------------------------
write_result:
    call append_u16
    mov rsi, r9
    mov edx, r10d
    call buf_write
    ret

; -------------------------------------------------------------------
; write_open_intel  ax=port
; -------------------------------------------------------------------
write_open_intel:
    call append_u16
    lea rsi, [open_ttl_msg]
    mov edx, open_ttl_len
    call buf_write
    movzx ax, byte [last_ttl]
    call append_u16
    lea rsi, [open_win_msg]
    mov edx, open_win_len
    call buf_write
    mov ax, [last_win]
    call append_u16
    cmp byte [os_enabled], 0
    je .no_os
    lea rsi, [os_prefix_msg]
    mov edx, os_prefix_len
    call buf_write
    movzx eax, byte [os_result_idx]
    cmp eax, 6
    jbe .os_ok
    mov eax, 6
.os_ok:
    mov rsi, [os_str_ptrs + rax*8]
    xor edx, edx
.strlen:
    cmp byte [rsi+rdx], 0
    je .strlen_done
    inc edx
    jmp .strlen
.strlen_done:
    call buf_write
.no_os:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

; -------------------------------------------------------------------
; record_open
; -------------------------------------------------------------------
record_open:
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    or byte [result_map+rax], r8b
    inc dword [open_count]
    ret

; -------------------------------------------------------------------
; write_summary
; -------------------------------------------------------------------
write_summary:
    lea rsi, [open_count_msg]
    mov edx, open_count_len
    call buf_write
    mov ax, [open_count]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    mov ax, [open_count]
    test ax, ax
    jz .none
    lea rsi, [open_ports_msg]
    mov edx, open_ports_len
    call buf_write
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
.loop:
    cmp ecx, r15d
    ja .done
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    test byte [result_map+rax], r8b
    jz .next
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
.next:
    inc ecx
    jmp .loop
.done:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret
.none:
    lea rsi, [open_ports_msg]
    mov edx, open_ports_len
    call buf_write
    lea rsi, [none_msg]
    mov edx, none_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

; -------------------------------------------------------------------
; write_bench
; -------------------------------------------------------------------
write_bench:
    lea rsi, [bench_hdr_msg]
    mov edx, bench_hdr_len
    call buf_write
    lea rsi, [bench_ports_msg]
    mov edx, bench_ports_len
    call buf_write
    mov ax, [end_port]
    mov bx, [start_port]
    sub ax, bx
    inc ax
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [bench_open_msg]
    mov edx, bench_open_len
    call buf_write
    mov ax, [open_count]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [bench_time_msg]
    mov edx, bench_time_len
    call buf_write
    mov rax, [bench_end_tsc]
    sub rax, [bench_start_tsc]
    mov rcx, 1000
    mul rcx
    mov rcx, [tsc_hz]
    test rcx, rcx
    jz .no_time
    div rcx
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
.no_time:
    lea rsi, [bench_end_msg]
    mov edx, bench_end_len
    call buf_write
    ret

; -------------------------------------------------------------------
; fingerprint_os  (same scoring as Linux version)
; -------------------------------------------------------------------
fingerprint_os:
    push rbx
    push r12
    push r13
    movzx r12d, byte [last_ttl]
    movzx r13d, word [last_win]
    xor ebx, ebx
    cmp r12d, 70
    jbe .ttl_done
    mov ebx, 1
    cmp r12d, 130
    jbe .ttl_done
    mov ebx, 2
.ttl_done:
    xor eax, eax
    mov byte [os_result_idx], 6

    ; Linux 5.x/6.x
    xor ecx, ecx
    cmp r13d, 64240
    jne .l5b
    inc ecx
.l5b:
    cmp r13d, 29200
    jne .l5s
    inc ecx
.l5s:
    test ebx, ebx
    jnz .l5e
    inc ecx
    cmp ecx, eax
    jbe .l5e
    mov eax, ecx
    mov byte [os_result_idx], 0
.l5e:
    ; Linux 3.x/4.x
    xor ecx, ecx
    cmp r13d, 29200
    je .l3w
    cmp r13d, 65535
    jne .l3s
.l3w:
    inc ecx
.l3s:
    test ebx, ebx
    jnz .l3e
    inc ecx
    cmp ecx, eax
    jbe .l3e
    mov eax, ecx
    mov byte [os_result_idx], 1
.l3e:
    ; Windows 10/11
    xor ecx, ecx
    cmp r13d, 65535
    je .w10w
    cmp r13d, 64240
    jne .w10s
.w10w:
    inc ecx
.w10s:
    cmp ebx, 1
    jne .w10e
    inc ecx
    cmp ecx, eax
    jbe .w10e
    mov eax, ecx
    mov byte [os_result_idx], 2
.w10e:
    ; Windows 7/8
    xor ecx, ecx
    cmp r13d, 8192
    je .w7w
    cmp r13d, 16384
    jne .w7s
.w7w:
    inc ecx
.w7s:
    cmp ebx, 1
    jne .w7e
    inc ecx
    cmp ecx, eax
    jbe .w7e
    mov eax, ecx
    mov byte [os_result_idx], 3
.w7e:
    ; macOS/BSD
    xor ecx, ecx
    cmp r13d, 65228
    je .mw
    cmp r13d, 65535
    jne .ms
.mw:
    inc ecx
.ms:
    test ebx, ebx
    jnz .me
    inc ecx
    cmp ecx, eax
    jbe .me
    mov eax, ecx
    mov byte [os_result_idx], 4
.me:
    ; Network device
    xor ecx, ecx
    cmp ebx, 2
    jne .de
    add ecx, 2
    cmp ecx, eax
    jbe .de
    mov byte [os_result_idx], 5
.de:
    pop r13
    pop r12
    pop rbx
    ret

; -------------------------------------------------------------------
; print_about
; -------------------------------------------------------------------
print_about:
    lea rsi, [banner_msg]
    mov edx, banner_len
    call write_stdout
    lea rsi, [about_msg]
    mov edx, about_len
    call write_stdout
    ret

; -------------------------------------------------------------------
; is_about_mode  rdi -> eax=1 if "--about"
; -------------------------------------------------------------------
is_about_mode:
    cmp dword [rdi],   '--ab'
    jne .no
    cmp dword [rdi+4], 'out'
    jne .no
    cmp byte  [rdi+6], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; -------------------------------------------------------------------
; rsi=prompt_str, edx=prompt_len, rdi=dest_buf, ecx=buf_size
; returns eax=1 if non-empty input, 0 if empty or error
; -------------------------------------------------------------------
prompt_read_line:
    push rbx
    mov rbx, rdi
    mov r10d, ecx
    call write_stdout
    dec r10d
    sub rsp, 40
    mov rcx, [stdin_handle]
    mov rdx, rbx
    mov r8d, r10d
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile
    add rsp, 40
    test eax, eax
    jz .none
    mov eax, [bytes_read]
    test eax, eax
    jz .none
    mov ecx, eax
    mov byte [rbx+rcx], 0
    mov rdi, rbx
    call trim_line
    mov al, [rbx]
    test al, al
    setnz al
    movzx eax, al
    pop rbx
    ret
.none:
    mov byte [rbx], 0
    xor eax, eax
    pop rbx
    ret

; -------------------------------------------------------------------
; rdi=buffer, strips trailing \r and \n
; -------------------------------------------------------------------
trim_line:
    mov al, [rdi]
    test al, al
    jz .done
    cmp al, 10
    je .term
    cmp al, 13
    je .term
    inc rdi
    jmp trim_line
.term:
    mov byte [rdi], 0
.done:
    ret

; -------------------------------------------------------------------
; rdi -> arg string, returns eax=1 if matches --wizard
; -------------------------------------------------------------------
is_wizard_mode:
    cmp dword [rdi],   '--wi'
    jne .no
    cmp dword [rdi+4], 'zard'
    jne .no
    cmp byte  [rdi+8], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; -------------------------------------------------------------------
; wizard_flow
; Returns eax=0 on success, 1 on failure/abort
; -------------------------------------------------------------------
wizard_flow:
    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write
    lea rsi, [wizard_hdr]
    mov edx, wizard_hdr_len
    call buf_write

    ; Question 1: target IP
    lea rsi, [wiz_q_target]
    mov edx, wiz_q_target_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .invalid
    lea rdi, [input_buf]
    call parse_ip
    test eax, eax
    jz .invalid
    mov [target_ip], eax
    ; copy raw input into wiz_target_str (max 15 chars)
    lea rsi, [input_buf]
    lea rdi, [wiz_target_str]
    mov ecx, 15
.copy_ip:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ip_copied
    inc rsi
    inc rdi
    loop .copy_ip
    mov byte [rdi], 0
.ip_copied:

    ; Question 2: port range
    lea rsi, [wiz_q_ports]
    mov edx, wiz_q_ports_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .ports_default
    cmp byte [input_buf], '-'
    jne .ports_parse
    cmp byte [input_buf+1], 0
    jne .ports_parse
    mov word [start_port], 1
    mov word [end_port], 65535
    jmp .ports_done
.ports_parse:
    lea rdi, [input_buf]
    call parse_port_range
    test ax, ax
    jz .invalid
    mov [start_port], ax
    mov [end_port], dx
    jmp .ports_done
.ports_default:
    mov word [start_port], 1
    mov word [end_port], 1000
.ports_done:

    ; Question 3: scan mode
    lea rsi, [wiz_q_mode]
    mov edx, wiz_q_mode_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .mode_default
    lea rdi, [input_buf]
    call parse_scan_mode
    test al, al
    jz .invalid
    mov [scan_mode], al
    jmp .mode_done
.mode_default:
    mov byte [scan_mode], SCAN_SYN
.mode_done:

    ; Question 4: rate
    lea rsi, [wiz_q_rate]
    mov edx, wiz_q_rate_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .rate_unlim
    cmp byte [input_buf], '0'
    jne .rate_parse
    cmp byte [input_buf+1], 0
    je .rate_unlim
.rate_parse:
    lea rdi, [input_buf]
    call parse_u32
    mov [rate_value], eax
    jmp .rate_done
.rate_unlim:
    xor eax, eax
    mov [rate_value], eax
.rate_done:

    ; Question 5: OS fingerprint
    lea rsi, [wiz_q_os]
    mov edx, wiz_q_os_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .os_done
    mov al, [input_buf]
    or al, 0x20
    cmp al, 'y'
    jne .os_done
    mov byte [os_enabled], 1
.os_done:

    ; Question 6: benchmark
    lea rsi, [wiz_q_bench]
    mov edx, wiz_q_bench_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .bench_done
    mov al, [input_buf]
    or al, 0x20
    cmp al, 'y'
    jne .bench_done
    mov byte [bench_enabled], 1
.bench_done:

    ; Question 7: stabilizer
    lea rsi, [wiz_q_stab]
    mov edx, wiz_q_stab_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .stab_done
    mov al, [input_buf]
    or al, 0x20
    cmp al, 'y'
    jne .stab_done
    mov byte [stab_enabled], 1
.stab_done:

    ; Print summary
    lea rsi, [wiz_summary_hdr]
    mov edx, wiz_summary_hdr_len
    call buf_write

    lea rsi, [wiz_sum_target]
    mov edx, wiz_sum_target_len
    call buf_write
    lea rsi, [wiz_target_str]
    xor edx, edx
.target_len:
    cmp byte [rsi+rdx], 0
    je .target_len_done
    inc edx
    jmp .target_len
.target_len_done:
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    lea rsi, [wiz_sum_ports]
    mov edx, wiz_sum_ports_len
    call buf_write
    mov ax, [start_port]
    call append_u16
    lea rsi, [wiz_dash]
    mov edx, wiz_dash_len
    call buf_write
    mov ax, [end_port]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    lea rsi, [wiz_sum_mode]
    mov edx, wiz_sum_mode_len
    call buf_write
    movzx eax, byte [scan_mode]
    lea rsi, [wiz_mode_ptrs]
    mov rsi, [rsi + rax*8]
    xor edx, edx
.mode_len:
    cmp byte [rsi+rdx], 0
    je .mode_len_done
    inc edx
    jmp .mode_len
.mode_len_done:
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    lea rsi, [wiz_sum_rate]
    mov edx, wiz_sum_rate_len
    call buf_write
    mov eax, [rate_value]
    test eax, eax
    jz .rate_unlim_print
    mov ax, [rate_value]
    call append_u16
    jmp .rate_print_done
.rate_unlim_print:
    lea rsi, [wiz_unlim]
    mov edx, wiz_unlim_len
    call buf_write
.rate_print_done:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    lea rsi, [wiz_sum_flags]
    mov edx, wiz_sum_flags_len
    call buf_write
    mov byte [wiz_any_flag], 0
    cmp byte [os_enabled], 0
    je .no_os_flag
    lea rsi, [wiz_flag_os]
    mov edx, wiz_flag_os_len
    call buf_write
    mov byte [wiz_any_flag], 1
.no_os_flag:
    cmp byte [bench_enabled], 0
    je .no_bench_flag
    lea rsi, [wiz_flag_bench]
    mov edx, wiz_flag_bench_len
    call buf_write
    mov byte [wiz_any_flag], 1
.no_bench_flag:
    cmp byte [stab_enabled], 0
    je .no_stab_flag
    lea rsi, [wiz_flag_stab]
    mov edx, wiz_flag_stab_len
    call buf_write
    mov byte [wiz_any_flag], 1
.no_stab_flag:
    cmp byte [wiz_any_flag], 0
    jne .flags_done
    lea rsi, [wiz_flag_none]
    mov edx, wiz_flag_none_len
    call buf_write
.flags_done:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    ; Confirmation
    lea rsi, [wiz_confirm]
    mov edx, wiz_confirm_len
    call buf_write
    call flush_output
    sub rsp, 40
    mov rcx, [stdin_handle]
    lea rdx, [input_buf]
    mov r8d, 1
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile
    add rsp, 40
    mov al, [input_buf]
    or al, 0x20
    cmp al, 'y'
    jne .abort

    lea rsi, [wiz_starting]
    mov edx, wiz_starting_len
    call buf_write
    call flush_output
    xor eax, eax
    ret

.abort:
    lea rsi, [wiz_abort]
    mov edx, wiz_abort_len
    call buf_write
    call flush_output
    mov eax, 1
    ret

.invalid:
    lea rsi, [prompt_invalid]
    mov edx, prompt_invalid_len
    call buf_write
    call flush_output
    mov eax, 1
    ret

; -------------------------------------------------------------------
; icmp_host_probe
; -------------------------------------------------------------------
icmp_host_probe:
    push rbx
    push r12
    lea rsi, [disc_hdr_msg]
    mov edx, disc_hdr_len
    call buf_write
    mov r12b, [engine_id]
    mov bl, [scan_mode]
    mov byte [engine_id], ENGINE_ICMP
    xor ax, ax
    mov [dst_port_be], ax
    call build_icmp_packet
    call intel_rtt_start

    ; sendto
    mov edx, 60
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [packet_buf]
    mov r8d, edx
    lea rdx, [packet_buf]
    xor r9d, r9d
    lea rax, [sockaddr_dst]
    mov [rsp+32], rax
    mov qword [rsp+40], 16
    call sendto
    add rsp, 56

    mov byte [host_up_map], 0
    ; recvfrom with timeout (SO_RCVTIMEO)
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [recv_buf]
    mov r8d, 4096
    xor r9d, r9d
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    call recvfrom
    add rsp, 56
    cmp eax, SOCKET_ERROR
    je .print_down

    lea rsi, [recv_buf]
    mov al, [rsi+9]
    cmp al, 1
    jne .print_down
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .print_down
    mov al, [rsi+20]
    cmp al, 0
    jne .print_down
    mov byte [host_up_map], 1
    mov al, [rsi+8]
    mov [last_ttl], al
    call intel_rtt_record

    lea rsi, [wiz_target_str]
    xor edx, edx
.ip_len:
    cmp byte [rsi+rdx], 0
    je .ip_len_done
    inc edx
    jmp .ip_len
.ip_len_done:
    call buf_write
    lea rsi, [disc_up_msg]
    mov edx, disc_up_len
    call buf_write
    movzx ax, byte [last_ttl]
    call append_u16
    lea rsi, [disc_rtt_msg]
    mov edx, disc_rtt_len
    call buf_write
    xor ax, ax
    call append_u16
    lea rsi, [disc_ms_msg]
    mov edx, disc_ms_len
    call buf_write
    jmp .restore

.print_down:
    lea rsi, [wiz_target_str]
    xor edx, edx
.ip_len2:
    cmp byte [rsi+rdx], 0
    je .ip_len2_done
    inc edx
    jmp .ip_len2
.ip_len2_done:
    call buf_write
    lea rsi, [disc_down_msg]
    mov edx, disc_down_len
    call buf_write

.restore:
    mov [engine_id], r12b
    mov [scan_mode], bl
    pop r12
    pop rbx
    ret

; -------------------------------------------------------------------
; json_print_header
; -------------------------------------------------------------------
json_print_header:
    cmp byte [json_mode], 0
    je .done
    lea rsi, [json_open_brace]
    mov edx, json_open_len
    call buf_write
    lea rsi, [json_target_key]
    mov edx, json_target_klen
    call buf_write
    lea rsi, [wiz_target_str]
    xor edx, edx
.target_len:
    cmp byte [rsi+rdx], 0
    je .target_len_done
    inc edx
    jmp .target_len
.target_len_done:
    call buf_write
    lea rsi, [json_target_end]
    mov edx, json_target_elen
    call buf_write
    lea rsi, [json_ports_key]
    mov edx, json_ports_klen
    call buf_write
.done:
    ret

; -------------------------------------------------------------------
; json_print_footer
; -------------------------------------------------------------------
json_print_footer:
    cmp byte [json_mode], 0
    je .done
    lea rsi, [json_ports_end]
    mov edx, json_ports_elen
    call buf_write
    lea rsi, [json_close_brace]
    mov edx, json_close_len
    call buf_write
.done:
    ret

; -------------------------------------------------------------------
; json_print_port
; Input: ecx=port, al=state (1=open,2=closed,3=filtered)
; -------------------------------------------------------------------
json_print_port:
    cmp byte [json_mode], 0
    je .done
    mov bl, al
    cmp byte [json_first_port], 0
    jne .first_ok
    lea rsi, [json_comma_nl]
    mov edx, json_comma_nl_len
    call buf_write
    jmp .after_first
.first_ok:
    mov byte [json_first_port], 0
.after_first:
    lea rsi, [json_port_open]
    mov edx, json_port_oplen
    call buf_write
    mov ax, cx
    call append_u16
    cmp bl, 1
    jne .state_closed
    lea rsi, [json_state_open]
    mov edx, json_state_oplen
    call buf_write
    jmp .state_done
.state_closed:
    cmp bl, 2
    jne .state_filt
    lea rsi, [json_state_closed]
    mov edx, json_state_clen
    call buf_write
    jmp .state_done
.state_filt:
    lea rsi, [json_state_filt]
    mov edx, json_state_flen
    call buf_write
.state_done:
    lea rsi, [json_ttl_key]
    mov edx, json_ttl_klen
    call buf_write
    movzx ax, byte [last_ttl]
    call append_u16
    lea rsi, [json_close_obj]
    mov edx, json_close_olen
    call buf_write
.done:
    ret

; -------------------------------------------------------------------
; csv_print_port
; -------------------------------------------------------------------
csv_print_port:
    cmp byte [csv_mode], 0
    je .done
    mov bl, al
    lea rsi, [wiz_target_str]
    xor edx, edx
.csv_ip_len:
    cmp byte [rsi+rdx], 0
    je .csv_ip_len_done
    inc edx
    jmp .csv_ip_len
.csv_ip_len_done:
    call buf_write
    lea rsi, [csv_comma]
    mov edx, csv_comma_len
    call buf_write
    mov ax, cx
    call append_u16
    cmp bl, 1
    jne .csv_closed
    lea rsi, [csv_open_str]
    mov edx, csv_open_len
    call buf_write
    jmp .csv_state_done
.csv_closed:
    cmp bl, 2
    jne .csv_filt
    lea rsi, [csv_closed_str]
    mov edx, csv_closed_len
    call buf_write
    jmp .csv_state_done
.csv_filt:
    lea rsi, [csv_filt_str]
    mov edx, csv_filt_len
    call buf_write
.csv_state_done:
    movzx ax, byte [last_ttl]
    call append_u16
    lea rsi, [csv_comma]
    mov edx, csv_comma_len
    call buf_write
    xor ax, ax
    call append_u16
    lea rsi, [csv_comma]
    mov edx, csv_comma_len
    call buf_write
    cmp byte [os_enabled], 0
    je .csv_no_os
    movzx eax, byte [os_result_idx]
    cmp eax, 6
    jbe .csv_os_ok
    mov eax, 6
.csv_os_ok:
    mov rsi, [os_str_ptrs + rax*8]
    xor edx, edx
.csv_os_len:
    cmp byte [rsi+rdx], 0
    je .csv_os_len_done
    inc edx
    jmp .csv_os_len
.csv_os_len_done:
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    jmp .done
.csv_no_os:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
.done:
    ret
; ===========================================================================
; NetroX-ASM  |  Windows x86_64  |  Part 4 of 4: Rate, stabilize, helpers, TSC
; ===========================================================================

; -------------------------------------------------------------------
; intelligence_gate
; -------------------------------------------------------------------
intelligence_gate:
    call rate_gate
    ret

; -------------------------------------------------------------------
; rate_gate  -  RDTSC-based packet rate limiter
; -------------------------------------------------------------------
rate_gate:
    cmp byte [rate_enabled], 0
    je .done
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, [last_send_tsc]
    test r8, r8
    jz .store
.wait:
    mov r9, rax
    sub r9, r8
    cmp r9, [rate_cycles]
    jae .store
    rdtsc
    shl rdx, 32
    or rax, rdx
    jmp .wait
.store:
    mov [last_send_tsc], rax
.done:
    ret

; -------------------------------------------------------------------
; cookie_init
; -------------------------------------------------------------------
cookie_init:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [scan_seed], rax
    ret

; -------------------------------------------------------------------
; cookie_generate
; Input:  ecx = destination port (host order)
;         rdi = destination IP
; Output: eax = 32-bit cookie
; -------------------------------------------------------------------
cookie_generate:
    push rbx
    mov  rax, [local_ip]
    xor  rax, rdi
    movzx rbx, cx
    xor  rax, rbx
    xor  rax, [scan_seed]
    mov  rbx, rax
    shl  rbx, 13
    xor  rax, rbx
    mov  rbx, rax
    shr  rbx, 7
    xor  rax, rbx
    mov  rbx, rax
    shl  rbx, 17
    xor  rax, rbx
    and  eax, 0xFFFFFFFF
    pop  rbx
    ret

; -------------------------------------------------------------------
; cookie_verify
; Input:  ecx = destination port
;         edx = ack number
; Output: ZF=1 if valid response
; -------------------------------------------------------------------
cookie_verify:
    push rax
    call cookie_generate
    inc  eax
    cmp  edx, eax
    pop  rax
    ret

; -------------------------------------------------------------------
; get_local_ip
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
get_local_ip:
    push rbx
    sub rsp, 40
    mov ecx, AF_INET
    mov edx, SOCK_DGRAM
    mov r8d, IPPROTO_UDP
    call socket
    add rsp, 40
    cmp rax, INVALID_SOCKET
    je .fail
    mov rbx, rax

    mov word [sockaddr_tmp], AF_INET
    mov word [sockaddr_tmp+2], 0x3500
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    sub rsp, 40
    mov rcx, rbx
    lea rdx, [sockaddr_tmp]
    mov r8d, 16
    call connect
    add rsp, 40
    test eax, eax
    jne .cleanup

    mov dword [addrlen], 16
    sub rsp, 40
    mov rcx, rbx
    lea rdx, [sockaddr_local]
    lea r8, [addrlen]
    call getsockname
    add rsp, 40
    test eax, eax
    jne .cleanup

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    sub rsp, 40
    mov rcx, rbx
    call closesocket
    add rsp, 40
    pop rbx
    xor eax, eax
    ret

.cleanup:
    sub rsp, 40
    mov rcx, rbx
    call closesocket
    add rsp, 40
.fail:
    pop rbx
    mov eax, 1
    ret

; -------------------------------------------------------------------
; stabilize_step
; -------------------------------------------------------------------
stabilize_step:
    cmp byte [stab_enabled], 0
    je .done
    cmp byte [rate_enabled], 0
    je .done
    push rcx
    mov eax, [stab_sent]
    test eax, eax
    jz .restore
    xor edx, edx
    mov ecx, 128
    div ecx
    test edx, edx
    jne .restore
    mov eax, [stab_timeout]
    mov ecx, [stab_recv]
    lea edx, [ecx*2]
    cmp eax, edx
    ja .slow
    lea edx, [eax*2]
    cmp ecx, edx
    ja .fast
    jmp .reset
.slow:
    call slow_down
    jmp .reset
.fast:
    call speed_up
.reset:
    mov dword [stab_sent], 0
    mov dword [stab_recv], 0
    mov dword [stab_timeout], 0
.restore:
    pop rcx
.done:
    ret

slow_down:
    mov rax, [rate_cycles]
    mov rcx, rax
    shr rcx, 2
    add rax, rcx
    mov rdx, [rate_max_cycles]
    test rdx, rdx
    jz .store
    cmp rax, rdx
    jbe .store
    mov rax, rdx
.store:
    mov [rate_cycles], rax
    ret

speed_up:
    mov rax, [rate_cycles]
    mov rcx, rax
    shr rcx, 3
    sub rax, rcx
    mov rdx, [rate_min_cycles]
    test rdx, rdx
    jz .store
    cmp rax, rdx
    jae .store
    mov rax, rdx
.store:
    mov [rate_cycles], rax
    ret

; -------------------------------------------------------------------
; init_rate
; -------------------------------------------------------------------
init_rate:
    mov eax, [rate_value]
    test eax, eax
    jnz .do
    mov al, [timing_level]
    test al, al
    jz .timing_done
    cmp al, 1
    jne .t2
    mov eax, [timing_t1_rate]
    mov [rate_value], eax
    jmp .timing_done
.t2:
    cmp al, 2
    jne .t3
    mov eax, [timing_t2_rate]
    mov [rate_value], eax
    jmp .timing_done
.t3:
    cmp al, 3
    jne .t4
    mov eax, [timing_t3_rate]
    mov [rate_value], eax
    jmp .timing_done
.t4:
    cmp al, 4
    jne .t5
    mov eax, [timing_t4_rate]
    mov [rate_value], eax
    jmp .timing_done
.t5:
    mov eax, [timing_t5_rate]
    mov [rate_value], eax
.timing_done:
    cmp byte [stab_enabled], 0
    je .done
    mov dword [rate_value], 200000
    mov eax, [rate_value]
.do:
    call calibrate_tsc
    mov ecx, [rate_value]
    mov rax, [tsc_hz]
    xor rdx, rdx
    div rcx
    mov [rate_cycles], rax
    mov byte [rate_enabled], 1
    cmp byte [stab_enabled], 0
    je .done
    mov rax, [rate_cycles]
    mov rcx, rax
    shl rcx, 2
    mov [rate_max_cycles], rcx
    mov rcx, rax
    shr rcx, 2
    mov [rate_min_cycles], rcx
.done:
    ret

; -------------------------------------------------------------------
; calibrate_tsc
; -------------------------------------------------------------------
calibrate_tsc:
    sub rsp, 40
    lea rcx, [qpc_freq]
    call QueryPerformanceFrequency
    add rsp, 40
    test eax, eax
    jz .done

    sub rsp, 40
    lea rcx, [qpc_start]
    call QueryPerformanceCounter
    add rsp, 40
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [tsc_start], rax

    mov rax, [qpc_freq]
    xor rdx, rdx
    mov r10, 20
    div r10
    mov r11, rax

.loop:
    sub rsp, 40
    lea rcx, [qpc_end]
    call QueryPerformanceCounter
    add rsp, 40
    mov rax, [qpc_end]
    sub rax, [qpc_start]
    cmp rax, r11
    jb .loop
    mov r8, rax

    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r9, rax
    mov rax, r9
    sub rax, [tsc_start]
    mov rcx, [qpc_freq]
    mul rcx
    mov rcx, r8
    div rcx
    mov [tsc_hz], rax
.done:
    ret

; -------------------------------------------------------------------
; blackrock_init
; -------------------------------------------------------------------
blackrock_init:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, rax
    mov rcx, 6
    lea rdi, [blackrock_key_0]
.keygen:
    mov rax, r8
    shl rax, 13
    xor r8, rax
    mov rax, r8
    shr rax, 7
    xor r8, rax
    mov rax, r8
    shl rax, 17
    xor r8, rax
    mov [rdi], r8
    add rdi, 8
    loop .keygen
    ret

; -------------------------------------------------------------------
; feistel_f
; -------------------------------------------------------------------
feistel_f:
    mov rax, r9
    add rax, r10
    mov rcx, 0x9e3779b97f4a7c15
    mul rcx
    xor rax, rdx
    rol rax, 17
    ret

; -------------------------------------------------------------------
; blackrock_permute
; -------------------------------------------------------------------
blackrock_permute:
    push rbx
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi

    mov rbx, r12
    and rbx, 0xFF
    mov rcx, r12
    shr rcx, 8
    and rcx, 0xFF

    %assign round 0
    %rep 6
        mov r9, rcx
        mov r10, [blackrock_key_ %+ round]
        call feistel_f
        xor rbx, rax
        and rbx, 0xFF
        xchg rbx, rcx
        %assign round round+1
    %endrep

    shl rcx, 8
    or rcx, rbx
.cycle_walk:
    cmp rcx, r13
    jb .done
    inc rcx
    cmp rcx, r13
    jb .done
    xor rcx, rcx
.done:
    mov rax, rcx
    pop r13
    pop r12
    pop rbx
    ret

; -------------------------------------------------------------------
; next_token  rdi=command-line string
; Splits on spaces, handles "quoted tokens"
; Returns rax=token_start (null-terminated in place), rdx=next_pos
; Returns rax=0 if no more tokens
; -------------------------------------------------------------------
next_token:
    ; Skip leading spaces
.skip:
    mov al, [rdi]
    cmp al, 0
    je .none
    cmp al, ' '
    jne .start
    inc rdi
    jmp .skip

.start:
    cmp al, '"'
    jne .no_quote
    ; Quoted token: skip opening quote, scan to closing quote
    inc rdi
    mov rax, rdi
.scan_quoted:
    mov al, [rdi]
    cmp al, 0
    je .quoted_eos
    cmp al, '"'
    je .quoted_end
    inc rdi
    jmp .scan_quoted
.quoted_end:
    mov byte [rdi], 0
    inc rdi
    mov rdx, rdi
    ret
.quoted_eos:
    mov rdx, rdi
    ret

.no_quote:
    ; Unquoted token: scan to space or end
    mov rax, rdi
.scan:
    mov al, [rdi]
    cmp al, 0
    je .eos
    cmp al, ' '
    je .token_end
    inc rdi
    jmp .scan
.token_end:
    mov byte [rdi], 0
    inc rdi
.eos:
    mov rdx, rdi
    ret

.none:
    xor eax, eax
    mov rdx, rdi
    ret
