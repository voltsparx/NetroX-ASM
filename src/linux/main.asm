; ===========================================================================
; NetroX-ASM  |  Linux x86_64  |  Part 1 of 5: Headers, .data, .bss
; ===========================================================================

BITS 64
GLOBAL _start

%include "../common/constants.inc"
%include "../common/parse.inc"
%include "../common/checksum.inc"
%include "../common/packet.inc"
%include "../common/engine.inc"
%include "../common/intelligence.inc"

%define OUTPUT_BUF_SIZE         131072
%define OUTPUT_FLUSH_THRESHOLD   98304

; ---------------------------------------------------------------------------
; .data  -  all static strings and tunables
; ---------------------------------------------------------------------------
SECTION .data

usage_msg   db "Usage: netrox-asm <target_ip> [-p port|start-end|-]", 10
            db "       [--rate N] [--iface IFACE] [--scan MODE]", 10
            db "       [--bench] [--os] [--stabilize] [--about] [--wizard] [--callback]", 10
            db "Scan modes: syn ack fin null xmas window maimon udp ping sar kis phantom callback", 10
usage_len   equ $-usage_msg

banner_msg  db "   _  __    __           _  __    ___   ______  ___", 10
            db "  / |/ /__ / /________  | |/_/___/ _ | / __/  |/  /", 10
            db " /    / -_) __/ __/ _ \\_>  </___/ __ |_\\ \\/ /|_/ / ", 10
            db "/_/|_/\\__/\\__/_/  \\___/_/|_|   /_/ |_/___/_/  /_/  ", 10, 10
banner_len  equ $-banner_msg

about_msg   db "author : voltsparx", 10
            db "email  : voltsparx@gmail.com", 10
            db "repo   : https://github.com/voltsparx/NetroX-ASM", 10
            db "github : github.com/voltsparx", 10
about_len   equ $-about_msg

prompt_invalid    db "  Invalid input. Try again.", 10
prompt_invalid_len equ $-prompt_invalid

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

wiz_q_iface     db "  [8] Network interface (press Enter to skip): "
wiz_q_iface_len equ $-wiz_q_iface

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
disc_ms_msg     db "ms", 10, 0
disc_ms_len     equ $-disc_ms_msg
disc_down_msg   db " DOWN", 10, 0
disc_down_len   equ $-disc_down_msg
disc_hdr_msg    db "--- Host Discovery ---", 10, 0
disc_hdr_len    equ $-disc_hdr_msg

timing_t0_rate  dd 0
timing_t1_rate  dd 3
timing_t2_rate  dd 10
timing_t3_rate  dd 0
timing_t4_rate  dd 100000
timing_t5_rate  dd 0

json_open_brace   db "{", 10
json_open_len     equ $-json_open_brace
json_close_brace  db "}", 10
json_close_len    equ $-json_close_brace
json_target_key   db "  \"target\": \""
json_target_klen  equ $-json_target_key
json_target_end   db "\"", 10
json_target_elen  equ $-json_target_end
json_ports_key    db "  \"ports\": [", 10
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
json_ports_end    db "  ]", 10
json_ports_elen   equ $-json_ports_end
json_comma_nl     db ",", 10
json_comma_nl_len equ $-json_comma_nl

csv_header      db "ip,port,state,ttl,rtt_us,os", 10
csv_header_len  equ $-csv_header
csv_open_str    db ",open,"
csv_open_len    equ $-csv_open_str
csv_closed_str  db ",closed,"
csv_closed_len  equ $-csv_closed_str
csv_filt_str    db ",filtered,"
csv_filt_len    equ $-csv_filt_str
csv_comma       db ","
csv_comma_len   equ $-csv_comma

eng_status_msg  db "  Engine : ", 0
eng_seq_str     db "sequential", 10, 0
eng_async_str   db "async-epoll", 10, 0
eng_pipe_str    db "pipeline depth=", 0
eng_hybrid_str  db "hybrid (auto-select)", 10, 0
eng_newline     db 10, 0
eng_paren_close db ")", 10, 0
eng_auto_msg    db "  Auto-selected: ", 0
eng_rtt_msg     db "  Calibration: RTT=", 0
eng_loss_msg    db "us loss=", 0
eng_pct_msg     db "%", 10, 0

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

; Probe payloads
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

; Fuse reason strings
kis_fuse_r1       db "TTL shift detected", 0
kis_fuse_r2       db "Jitter explosion (>10%)", 0
kis_fuse_r3       db "Impedance spike (>5x baseline)", 0
kis_fuse_r4       db "Consecutive timeouts (5+)", 0
kis_fuse_r5       db "Baseline drift (>15%)", 0
kis_fuse_reason_ptrs:
    dq 0
    dq kis_fuse_r1, kis_fuse_r2, kis_fuse_r3
    dq kis_fuse_r4, kis_fuse_r5

; SJS service name strings
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

; SJS table compiled in
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

resume_msg    db 10, "[*] Scan paused. Resume with: netrox-asm --resume", 10, 0
resume_fname  db "netrox-asm.resume", 0
resume_idx_key db "resume-index = ", 0
resume_target_key db "target = ", 0
resume_ports_key db "ports = ", 0
resume_rate_key db "rate = ", 0
resume_scan_key db "scan = ", 0
resume_nl db 10, 0

config_sep        db " = ", 0
config_true_str   db "true", 0
config_yes_str    db "yes", 0

echo_hdr_msg     db "--- [ NETROX-ASM CONFIGURATION ] ---", 10, 0
echo_target_msg  db "Target     : ", 0
echo_scan_msg    db "Scan       : ", 0
echo_ports_msg   db "Ports      : ", 0
echo_rate_msg    db "Rate       : ", 0
echo_engine_msg  db "Engine     : ", 0
echo_timing_msg  db "Timing     : T", 0

scan_syn_str     db "syn", 0
scan_ack_str     db "ack", 0
scan_fin_str     db "fin", 0
scan_null_str    db "null", 0
scan_xmas_str    db "xmas", 0
scan_window_str  db "window", 0
scan_maimon_str  db "maimon", 0
scan_udp_str     db "udp", 0
scan_ping_str    db "ping", 0
scan_sar_str     db "sar", 0
scan_kis_str     db "kis", 0
scan_phantom_str db "phantom", 0
scan_callback_str db "callback", 0

; Result output strings
closed_msg      db " CLOSED", 10
closed_len      equ $-closed_msg
filtered_msg    db " FILTERED", 10
filtered_len    equ $-filtered_msg
open_ttl_msg    db " OPEN TTL="
open_ttl_len    equ $-open_ttl_msg
open_win_msg    db " WIN="
open_win_len    equ $-open_win_msg
newline_msg     db 10
newline_len     equ $-newline_msg
space_msg       db " "
space_len       equ $-space_msg
error_msg       db "ERROR", 10
error_len       equ $-error_msg

; Summary output strings
open_count_msg  db "OPEN COUNT: "
open_count_len  equ $-open_count_msg
open_ports_msg  db "OPEN PORTS: "
open_ports_len  equ $-open_ports_msg
none_msg        db "none"
none_len        equ $-none_msg

; OS fingerprint output
os_prefix_msg   db " OS="
os_prefix_len   equ $-os_prefix_msg

; Benchmark output
bench_hdr_msg   db 10, "--- NETX-ASM BENCHMARK ---", 10
bench_hdr_len   equ $-bench_hdr_msg
bench_ports_msg db "Ports scanned : "
bench_ports_len equ $-bench_ports_msg
bench_open_msg  db "Open found    : "
bench_open_len  equ $-bench_open_msg
bench_time_msg  db "Elapsed (ms)  : "
bench_time_len  equ $-bench_time_msg
bench_end_msg   db "--------------------------", 10
bench_end_len   equ $-bench_end_msg

; OS fingerprint string table (index 0-7)
os_str_0    db "Linux-5.x/6.x", 0
os_str_1    db "Linux-3.x/4.x", 0
os_str_2    db "Windows-10/11", 0
os_str_3    db "Windows-7/8",   0
os_str_4    db "macOS/BSD",      0
os_str_5    db "Network-Device", 0
os_str_6    db "Unknown",        0
os_str_ptrs dq os_str_0, os_str_1, os_str_2, os_str_3
            dq os_str_4, os_str_5, os_str_6

; Socket / packet tunables
hdrincl         dd 1
timeout_timeval dq 1, 0     ; 1 second receive timeout

src_port        dw 40000
dst_port        dw 0
start_port      dw 1
end_port        dw 1000
src_port_be     dw 0
dst_port_be     dw 0
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
; .rodata  -  read-only tables
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
; .bss  -  zero-initialised runtime buffers and variables
; ---------------------------------------------------------------------------
SECTION .bss

packet_buf      resb 60
recv_buf        resb 4096
out_buf         resb 16
output_buf      resb OUTPUT_BUF_SIZE
output_pos      resq 1

sockaddr_dst    resb 16
sockaddr_tmp    resb 16
sockaddr_local  resb 16
sockaddr_ll     resb 32
addrlen         resd 1

raw_fd          resq 1
send_fd         resq 1
epoll_fd        resq 1
epoll_event     resb 16
epoll_out       resb 16

target_ip       resd 1
source_ip       resd 1
last_ttl        resb 1
last_win        resw 1

result_map      resb 8192
open_count      resd 1

engine_id       resb 1
scan_mode       resb 1

; Rate control
rate_value      resd 1
rate_cycles     resq 1
rate_min_cycles resq 1
rate_max_cycles resq 1
rate_enabled    resb 1
last_send_tsc   resq 1
tsc_hz          resq 1
ts_start        resq 2
ts_end          resq 2
tsc_start       resq 1

; Interface
iface_name      resb 16
iface_set       resb 1
ifreq_buf       resb 40
ifindex         resd 1

; Stabilizer
stab_enabled    resb 1
stab_sent       resd 1
stab_recv       resd 1
stab_timeout    resd 1

; Prompt / flags

; Feature flags
bench_enabled   resb 1
os_enabled      resb 1

; Benchmark counters
bench_start_tsc resq 1
bench_end_tsc   resq 1

; OS fingerprint last result
os_result_idx   resb 1
os_score        resb 1
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
blackrock_key_0     resq 1
blackrock_key_1     resq 1
blackrock_key_2     resq 1
blackrock_key_3     resq 1
blackrock_key_4     resq 1
blackrock_key_5     resq 1
input_buf           resb 256
prompt_mode         resb 1
wiz_any_flag        resb 1
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

; Engine selection
engine_mode         resb 1

; Async engine
async_burst_cnt     resb 1
async_recv_ring     resb 32768

; Pipeline engine
pipe_slots          resb 2048
pipe_depth          resw 1
pipe_head           resw 1
pipe_tail           resw 1
pipe_inflight       resw 1

; In-flight tracker (shared by async + pipeline)
inflight_ports      resw 512
inflight_tsc_lo     resd 512
inflight_head       resw 1
inflight_tail       resw 1
inflight_count      resw 1
inflight_timeout_cy resq 1

; Hybrid calibration
hybrid_rtt_us       resd 1
hybrid_loss_pct     resb 1
hybrid_selected     resb 1

; Engine sub-options
par_sock_count      resb 1
thread_count_cfg    resb 1

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

; SAR result counters
sar_count_none      resd 1
sar_count_acl       resd 1
sar_count_stateful  resd 1
sar_count_dpi       resd 1
sar_count_ai        resd 1
sar_count_proxy     resd 1
sar_count_syncs     resd 1
sar_count_total     resd 1

; SAR result table
sar_results         resb 65535 * 16

; Waveform
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

; Result tracking
kis_count_closed     resd 1
kis_count_filtered   resd 1
kis_count_open       resd 1
kis_count_heavy      resd 1
kis_count_virt       resd 1
kis_count_unknown    resd 1
kis_count_total      resd 1

; Result table and heat map
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

; TEV state
tev_history               resw 8
tev_history_idx           resb 1
tev_consecutive_to        resb 1
tev_triggered             resb 1

; Phantom result counters
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

; Callback queue (16 slots * 8 bytes)
cb_queue              resb 128
cb_queue_head         resb 1
cb_queue_tail         resb 1
cb_queue_count        resb 1

; Subnet seen map (8192 bytes = one bit per /24)
cb_subnet_seen        resb 8192

; Callback counters
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

; Stateless cookie
scan_seed     resq 1
local_ip      resd 1

; CIDR ranges
ip_ranges         resb MAX_IP_RANGES * IP_RANGE_ENTRY
ip_range_count    resd 1
total_ip_count    resq 1
total_index_max   resq 1
cidr_mode         resb 1
current_scan_ip   resd 1

; Resume/pause
resume_index      resq 1
resume_filename   resb 256
resume_enabled    resb 1
resume_flag       resb 1
resume_fd         resq 1

; Config loader
config_filename   resb 256
config_enabled    resb 1
config_buf        resb 4096

; Additional flags
wait_secs         resb 1
banners_mode      resb 1
echo_mode         resb 1
random_host_count resd 1
version_enabled   resb 1
quiet_mode        resb 1

; ===========================================================================
; NetroX-ASM  |  Linux x86_64  |  Part 2 of 5: _start, arg parsing, init
; ===========================================================================

SECTION .text
_start:
    xor r12d, r12d

    mov rbx, rsp
    mov rax, [rbx]
    cmp rax, 2
    jb .usage

    call is_about_mode
    test eax, eax
    jnz .about_entry
    call is_wizard_mode
    test eax, eax
    jnz .wizard_entry

    mov rdi, [rbx+16]
    mov rsi, rdi
.cidr_scan:
    mov al, [rsi]
    test al, al
    jz .no_cidr
    cmp al, '/'
    je .has_cidr
    inc rsi
    jmp .cidr_scan
.has_cidr:
    call parse_cidr
    test eax, eax
    jz .usage
    mov byte [cidr_mode], 1
    mov eax, [ip_ranges]
    mov [target_ip], eax
    mov [current_scan_ip], eax
    jmp .target_ok
.no_cidr:
    call parse_ip
    test eax, eax
    jz .usage
    mov [target_ip], eax
    mov [current_scan_ip], eax
.target_ok:
    lea rsi, [rdi]
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

    mov r13, [rbx]
    mov rcx, 2

.arg_loop:
    cmp rcx, r13
    jae .ports_ready
    mov rdi, [rbx+rcx*8]
    cmp byte [rdi], '-'
    jne .arg_next

    ; -T<0-5>
    cmp byte [rdi+1], 'T'
    jne .check_p
    mov al, [rdi+2]
    cmp al, '0'
    jb .check_p
    cmp al, '5'
    ja .check_p
    sub al, '0'
    mov [timing_level], al
    ; map timing level to rate_value
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
    ; -p <port|range|->
    cmp byte [rdi+1], 'p'
    jne .check_rate
    cmp byte [rdi+2], 0
    jne .check_rate
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
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
    ; --rate N
    cmp byte [rdi+1], '-'
    jne .check_iface
    lea rsi, [rdi+2]
    cmp dword [rsi], 'rate'
    jne .check_iface
    cmp byte [rsi+4], 0
    jne .check_iface
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_u32
    test eax, eax
    jz .usage
    mov [rate_value], eax
    jmp .arg_next

.check_iface:
    ; --iface NAME
    cmp byte [rdi+1], '-'
    jne .check_scan
    lea rsi, [rdi+2]
    cmp dword [rsi], 'ifac'
    jne .check_scan
    cmp word [rsi+4], 'e'
    jne .check_scan
    cmp byte [rsi+5], 0
    jne .check_scan
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rsi, [rbx+rcx*8]
    call copy_iface_name
    test eax, eax
    jnz .usage
    mov byte [iface_set], 1
    jmp .arg_next

.check_scan:
    ; --scan MODE
    cmp byte [rdi+1], '-'
    jne .check_discovery
    lea rsi, [rdi+2]
    cmp dword [rsi], 'scan'
    jne .check_discovery
    cmp byte [rsi+4], 0
    jne .check_discovery
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_scan_mode
    test al, al
    jz .usage
    mov [scan_mode], al
    jmp .arg_next

.check_discovery:
    ; --discovery MODE
    cmp byte [rdi+1], '-'
    jne .check_top_ports
    lea rsi, [rdi+2]
    cmp dword [rsi], 'disc'
    jne .check_top_ports
    cmp dword [rsi+4], 'over'
    jne .check_top_ports
    cmp byte [rsi+8], 'y'
    jne .check_top_ports
    cmp byte [rsi+9], 0
    jne .check_top_ports
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    mov byte [disc_enabled], 1
    ; default to ping
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
    ; ping or unknown -> ping
    jmp .arg_next

.check_top_ports:
    ; --top-ports N
    cmp byte [rdi+1], '-'
    jne .check_bench
    lea rsi, [rdi+2]
    cmp dword [rsi], 'top-'
    jne .check_bench
    cmp dword [rsi+4], 'port'
    jne .check_bench
    cmp byte [rsi+8], 's'
    jne .check_bench
    cmp byte [rsi+9], 0
    jne .check_bench
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
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

.check_json:
    ; --json
    cmp byte [rdi+1], '-'
    jne .check_csv
    lea rsi, [rdi+2]
    cmp dword [rsi], 'json'
    jne .check_csv
    cmp byte [rsi+4], 0
    jne .check_csv
    mov byte [json_mode], 1
    mov byte [json_first_port], 1
    jmp .arg_next

.check_csv:
    ; --csv
    cmp byte [rdi+1], '-'
    jne .check_output
    lea rsi, [rdi+2]
    cmp dword [rsi], 'csv'
    jne .check_output
    cmp byte [rsi+3], 0
    jne .check_output
    mov byte [csv_mode], 1
    jmp .arg_next

.check_output:
    ; --output FILE
    cmp byte [rdi+1], '-'
    jne .check_retries
    lea rsi, [rdi+2]
    cmp dword [rsi], 'outp'
    jne .check_retries
    cmp dword [rsi+4], 'ut'
    jne .check_retries
    cmp byte [rsi+6], 0
    jne .check_retries
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rsi, [rbx+rcx*8]
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
    mov rax, SYS_OPEN
    lea rdi, [output_filename]
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0644
    syscall
    test rax, rax
    js .usage
    mov [output_fd], rax
    jmp .arg_next

.check_retries:
    ; --retries N
    cmp byte [rdi+1], '-'
    jne .check_bench
    lea rsi, [rdi+2]
    cmp dword [rsi], 'retr'
    jne .check_bench
    cmp dword [rsi+4], 'ies'
    jne .check_bench
    cmp byte [rsi+7], 0
    jne .check_bench
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_u32
    cmp eax, 6
    jbe .retry_set
    mov eax, 6
.retry_set:
    mov [retry_max], al
    jmp .arg_next
.top1000:
    lea rax, [top_1000_ports]
    mov [top_ports_ptr], rax
    mov byte [top_ports_mode], 1
    jmp .arg_next

.check_bench:
    ; --bench
    cmp byte [rdi+1], '-'
    jne .check_os
    lea rsi, [rdi+2]
    cmp dword [rsi], 'benc'
    jne .check_os
    cmp word [rsi+4], 'h'
    jne .check_os
    cmp byte [rsi+5], 0
    jne .check_os
    mov byte [bench_enabled], 1
    jmp .arg_next

.check_os:
    ; --os
    cmp byte [rdi+1], '-'
    jne .check_stabilize
    lea rsi, [rdi+2]
    cmp word [rsi], 'os'
    jne .check_stabilize
    cmp byte [rsi+2], 0
    jne .check_stabilize
    mov byte [os_enabled], 1
    jmp .arg_next

.check_callback:
    ; --callback
    cmp  byte [rdi+1], '-'
    jne  .check_engine
    cmp  dword [rdi+2], 'call'
    jne  .check_engine
    cmp  dword [rdi+6], 'back'
    jne  .check_engine
    cmp  byte  [rdi+10], 0
    jne  .check_engine
    mov  byte [cb_secondary_enabled], 1
    jmp  .arg_next

.check_resume:
    ; --resume
    cmp  byte [rdi+1], '-'
    jne  .check_config
    cmp  dword [rdi+2], 'resu'
    jne  .check_config
    cmp  dword [rdi+6], 'me'
    jne  .check_config
    cmp  byte  [rdi+8], 0
    jne  .check_config
    mov  byte [resume_enabled], 1
    jmp  .arg_next

.check_config:
    ; --config <file>
    cmp  byte [rdi+1], '-'
    jne  .check_wait
    cmp  dword [rdi+2], 'conf'
    jne  .check_wait
    cmp  word  [rdi+6], 'ig'
    jne  .check_wait
    cmp  byte  [rdi+8], 0
    jne  .check_wait
    inc  rcx
    cmp  rcx, r13
    jae  .usage
    mov  rsi, [rbx+rcx*8]
    lea  rdi, [config_filename]
    mov  ecx, 255
.cfg_copy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .cfg_done
    inc rsi
    inc rdi
    loop .cfg_copy
    mov byte [rdi], 0
.cfg_done:
    mov  byte [config_enabled], 1
    jmp  .arg_next

.check_wait:
    ; --wait N
    cmp  byte [rdi+1], '-'
    jne  .check_banners
    cmp  dword [rdi+2], 'wait'
    jne  .check_banners
    cmp  byte  [rdi+6], 0
    jne  .check_banners
    inc  rcx
    cmp  rcx, r13
    jae  .usage
    mov  rdi, [rbx+rcx*8]
    call parse_u32
    mov  [wait_secs], al
    jmp  .arg_next

.check_banners:
    ; --banners
    cmp  byte [rdi+1], '-'
    jne  .check_open
    cmp  dword [rdi+2], 'bann'
    jne  .check_open
    cmp  word  [rdi+6], 'ers'
    jne  .check_open
    cmp  byte  [rdi+8], 0
    jne  .check_open
    mov  byte [version_enabled], 1
    mov  byte [banners_mode], 1
    jmp  .arg_next

.check_open:
    ; --open / --open-only
    cmp  byte [rdi+1], '-'
    jne  .check_echo
    cmp  dword [rdi+2], 'open'
    jne  .check_echo
    mov  byte [quiet_mode], 1
    jmp  .arg_next

.check_echo:
    ; --echo
    cmp  byte [rdi+1], '-'
    jne  .check_iR
    cmp  dword [rdi+2], 'echo'
    jne  .check_iR
    cmp  byte  [rdi+6], 0
    jne  .check_iR
    mov  byte [echo_mode], 1
    jmp  .arg_next

.check_iR:
    ; -iR N
    cmp  byte [rdi], '-'
    jne  .check_engine
    cmp  byte [rdi+1], 'i'
    jne  .check_engine
    cmp  byte [rdi+2], 'R'
    jne  .check_engine
    cmp  byte [rdi+3], 0
    jne  .check_engine
    inc  rcx
    cmp  rcx, r13
    jae  .usage
    mov  rdi, [rbx+rcx*8]
    call parse_u32
    mov  [random_host_count], eax
    jmp  .arg_next

.check_engine:
    cmp byte [rdi+1], '-'
    jne .check_depth
    cmp dword [rdi+2], 'engi'
    jne .check_depth
    cmp word  [rdi+6], 'ne'
    jne .check_depth
    cmp byte  [rdi+8], 0
    jne .check_depth
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    cmp dword [rdi], 'asyn'
    jne .eng_chk_pipe
    mov byte [engine_mode], ENGINE_MODE_ASYNC
    jmp .arg_next
.eng_chk_pipe:
    cmp dword [rdi], 'pipe'
    jne .eng_chk_batch
    mov byte [engine_mode], ENGINE_MODE_PIPELINE
    jmp .arg_next
.eng_chk_batch:
    cmp dword [rdi], 'batc'
    jne .eng_chk_hybrid
    mov byte [engine_mode], ENGINE_MODE_BATCH
    jmp .arg_next
.eng_chk_hybrid:
    cmp dword [rdi], 'hybr'
    jne .eng_chk_seq
    mov byte [engine_mode], ENGINE_MODE_HYBRID
    jmp .arg_next
.eng_chk_seq:
    mov byte [engine_mode], ENGINE_MODE_ASYNC
    jmp .arg_next

.check_depth:
    ; --depth <n> for pipeline
    cmp byte [rdi+1], '-'
    jne .check_stabilize
    cmp dword [rdi+2], 'dept'
    jne .check_stabilize
    cmp byte  [rdi+6], 'h'
    jne .check_stabilize
    cmp byte  [rdi+7], 0
    jne .check_stabilize
    inc rcx
    cmp rcx, r13
    jae .usage
    mov rdi, [rbx+rcx*8]
    call parse_u32
    test eax, eax
    jz .usage
    cmp eax, PIPELINE_MAX_DEPTH
    jbe .depth_ok
    mov eax, PIPELINE_MAX_DEPTH
.depth_ok:
    mov [pipe_depth], ax
    jmp .arg_next

.check_stabilize:
    ; --stabilize
    cmp byte [rdi+1], '-'
    jne .arg_next
    lea rsi, [rdi+2]
    cmp dword [rsi],   'stab'
    jne .arg_next
    cmp dword [rsi+4], 'iliz'
    jne .arg_next
    cmp word  [rsi+8], 'e'
    jne .arg_next
    cmp byte  [rsi+9], 0
    jne .arg_next
    mov byte [stab_enabled], 1

.arg_next:
    inc rcx
    jmp .arg_loop

; -------------------------------------------------------------------
; All args parsed - set up engine and start scan
; -------------------------------------------------------------------
.ports_ready:
    cmp byte [config_enabled], 0
    je .skip_config
    call load_config_file
.skip_config:
    cmp byte [resume_enabled], 0
    je .skip_resume
    call read_resume_file
.skip_resume:
    cmp dword [random_host_count], 0
    je .skip_random_hosts
    call random_hosts_init
.skip_random_hosts:
    cmp byte [echo_mode], 0
    je .skip_echo
    call print_echo_config
.skip_echo:
    ; Convert src_port to big-endian
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax

    ; Set scan mode default
    cmp byte [scan_mode], 0
    jne .scan_mode_set
    mov byte [scan_mode], SCAN_SYN
.scan_mode_set:

    ; set default engine mode if not specified
    cmp byte [engine_mode], 0
    jne .engine_mode_set
    mov byte [engine_mode], ENGINE_MODE_ASYNC
.engine_mode_set:

    ; compute total_index_max for CIDR mode
    cmp byte [cidr_mode], 0
    je .cidr_done
    movzx rax, word [end_port]
    movzx rbx, word [start_port]
    sub rax, rbx
    inc rax                        ; port_count
    cmp byte [port_list_mode], 0
    je .cidr_ports_done
    movzx rax, word [port_list_count]
    jmp .cidr_ports_done
.cidr_ports_done:
    cmp byte [top_ports_mode], 0
    je .cidr_mul
    movzx rax, word [top_ports_n]
.cidr_mul:
    mov rbx, [total_ip_count]
    mul rbx
    mov [total_index_max], rax
.cidr_done:

    ; Set engine based on scan_mode
    mov byte [engine_id], ENGINE_SYN

    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write

    ; Detect local source IP
    call get_local_ip
    test eax, eax
    jnz .error
    mov eax, [source_ip]
    mov [local_ip], eax

    ; Init rate control and TSC calibration
    call init_rate
    call blackrock_init
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [xorshift_state], rax
    mov byte [batch_counter], 0
    call intel_init
    call inflight_init
    call print_engine_status
    call cookie_init

    ; Capture bench start TSC
    cmp byte [bench_enabled], 0
    je .after_bench_start
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [bench_start_tsc], rax
.after_bench_start:

    ; Open raw TCP socket (used for all scan types as recv socket)
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_RAW
    mov rdx, IPPROTO_TCP
    syscall
    test rax, rax
    js .error
    mov [raw_fd], rax

    ; IP_HDRINCL = 1
    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, IPPROTO_IP
    mov rdx, IP_HDRINCL
    lea r10, [hdrincl]
    mov r8, 4
    syscall
    test rax, rax
    js .error

    ; SO_RCVTIMEO = 1s
    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, SOL_SOCKET
    mov rdx, SO_RCVTIMEO
    lea r10, [timeout_timeval]
    mov r8, 16
    syscall

    ; epoll setup
    mov rax, SYS_EPOLL_CREATE1
    xor rdi, rdi
    syscall
    test rax, rax
    js .error
    mov [epoll_fd], rax

    mov dword [epoll_event], EPOLLIN | EPOLLET
    mov rax, [raw_fd]
    mov [epoll_event+8], rax
    mov rax, SYS_EPOLL_CTL
    mov rdi, [epoll_fd]
    mov rsi, EPOLL_CTL_ADD
    mov rdx, [raw_fd]
    lea r10, [epoll_event]
    syscall
    test rax, rax
    js .error

    call setup_sigint_handler

    ; Build IP/TCP template
    call init_packet_template

    ; sockaddr_dst: AF_INET + target_ip
    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    ; Setup send engine (raw or AF_PACKET if --iface)
    call setup_send_engine
    test eax, eax
    jnz .error

    cmp byte [disc_enabled], 0
    je .skip_discovery
    cmp byte [disc_mode], 1
    jne .skip_discovery
    call icmp_host_probe
    cmp byte [host_up_map], 0
    je .scan_done
.skip_discovery:
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

    ; dispatch to selected engine if not sequential
    cmp  byte [scan_mode], SCAN_SAR
    jne  .not_sar_direct
    call sar_init
    call sar_run
    jmp  .scan_done
.not_sar_direct:
    cmp  byte [scan_mode], SCAN_KIS
    jne  .not_kis_direct
    call kis_init
    call kis_run
    jmp  .scan_done
.not_kis_direct:
    cmp  byte [scan_mode], SCAN_PHANTOM
    jne  .not_phantom_direct
    call phantom_init
    call phantom_run
    jmp  .scan_done
.not_phantom_direct:
    cmp  byte [scan_mode], SCAN_CALLBACK
    jne  .not_callback_direct
    call cb_init
    call cb_run
    jmp  .scan_done
.not_callback_direct:
    cmp byte [engine_mode], ENGINE_MODE_SEQ
    je .use_seq_engine
    cmp byte [engine_mode], 0
    je .use_seq_engine
    call engine_run
    jmp .scan_done
.use_seq_engine:

    ; Load scan range into registers
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov r14d, r15d
    sub r14d, ecx
    inc r14d
    mov r15d, r14d
    mov r14d, ecx
    xor ebx, ebx
    xor r13, r13
    cmp byte [resume_flag], 0
    je .resume_done
    mov rbx, [resume_index]
.resume_done:
    cmp byte [port_list_mode], 0
    je .check_top_ports_mode
    lea r13, [port_list_buf]
    movzx r15d, word [port_list_count]
    xor r14d, r14d
    jmp .scan_ready
.check_top_ports_mode:
    cmp byte [top_ports_mode], 0
    je .scan_ready
    mov r13, [top_ports_ptr]
    movzx r15d, word [top_ports_n]
    xor r14d, r14d
.scan_ready:
    cmp byte [cidr_mode], 0
    je .scan_ready_done
    mov r15, [total_index_max]
    xor r14d, r14d
.scan_ready_done:
    ; fall through into scan loop (Part 3)

; ===========================================================================
; NetroX-ASM  |  Linux x86_64  |  Part 3 of 5: Scan loop, classify, OS FP
; ===========================================================================

; -------------------------------------------------------------------
; Main scan loop
; ecx = current port, r15d = end port
; -------------------------------------------------------------------
scan_loop_entry:
.scan_loop:
    cmp rbx, r15
    jae .scan_done
    mov [resume_index], rbx

    mov rdi, rbx
    mov rsi, r15
    call blackrock_permute
    cmp byte [cidr_mode], 0
    je .port_select
    call index_to_ip_port
    mov eax, [current_scan_ip]
    mov [packet_buf+16], eax
    mov [sockaddr_dst+4], eax
    jmp .port_ready
.port_select:
    test r13, r13
    jz .range_port
    movzx ecx, word [r13 + rax*2]
    jmp .port_ready
.range_port:
    add eax, r14d
    mov ecx, eax
.port_ready:
    mov ax, cx
    mov [dst_port], ax
    xchg al, ah
    mov [dst_port_be], ax

    mov [packet_buf+22], ax
    mov [sockaddr_dst+2], ax
    inc word [packet_buf+4]
    call fast_cksum_update

.retry_send:
    call intel_rtt_start
    call intelligence_gate

    movzx eax, byte [batch_counter]
    inc al
    cmp al, 64
    jb .batch_continue
    xor al, al
    xor r10d, r10d
    jmp .do_send
.batch_continue:
    mov r10d, MSG_MORE
.do_send:
    mov [batch_counter], al

    ; sendto
    mov rax, SYS_SENDTO
    mov rdi, [send_fd]
    lea rsi, [packet_buf]
    ; TCP packet length
    mov edx, 40
    cmp byte [iface_set], 0
    jne .send_ll
    lea r8, [sockaddr_dst]
    mov r9, 16
    jmp .send_do
.send_ll:
    lea r8, [sockaddr_ll]
    mov r9, 20
.send_do:
    syscall
    test rax, rax
    js .error

    cmp byte [stab_enabled], 0
    je .after_sent
    inc dword [stab_sent]
.after_sent:

    ; --- Receive phase: up to 8 epoll checks ---
    mov r11d, 8

.epoll_loop:
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov rdx, 1
    xor r10, r10
    syscall
    test rax, rax
    js .report_filtered
    cmp rax, 0
    je .epoll_noevent

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov rdx, 4096
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    test rax, rax
    js .report_filtered

    ; -------------------------------------------
    ; Decode received packet
    ; Check: IP protocol, source IP, ports
    ; -------------------------------------------
    lea rsi, [recv_buf]

    ; TCP response decode
    ; TCP response decode
    mov al, [rsi+9]
    cmp al, 6                           ; TCP
    jne .recv_mismatch
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .recv_mismatch
    ; Get IHL to find TCP header offset
    mov al, [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]                  ; rdx -> TCP header
    ; Check dest port == our src port
    mov ax, [rdx]
    cmp ax, [dst_port_be]
    jne .recv_mismatch
    mov ax, [rdx+2]
    cmp ax, [src_port_be]
    jne .recv_mismatch

    ; Capture TTL and window for intel output
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
    mov al, [rdx+13]                    ; TCP flags byte
    mov bl, al
    mov dl, [scan_mode]

    cmp dl, SCAN_SYN
    je .classify_syn
    cmp dl, SCAN_ACK
    je .classify_ack
    cmp dl, SCAN_WINDOW
    je .classify_ack
    ; FIN/NULL/XMAS/MAIMON: RST = CLOSED, no response = OPEN|FILTERED
    test bl, 0x04
    jnz .report_closed
    jmp .report_filtered

.classify_ack:
    test bl, 0x04                       ; RST = unfiltered
    jnz .report_open
    jmp .report_filtered

.classify_syn:
    and bl, 0x12
    cmp bl, 0x12                        ; SYN+ACK = OPEN
    je .report_open
    test al, 0x04                       ; RST = CLOSED
    jnz .report_closed
    jmp .report_filtered

.recv_mismatch:
    dec r11d
    jnz .epoll_loop
    jmp .report_filtered

.epoll_noevent:
    dec r11d
    jnz .epoll_loop
    jmp .report_filtered

; -------------------------------------------------------------------
; Report helpers
; -------------------------------------------------------------------
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
    inc rbx
    jmp .scan_loop

; -------------------------------------------------------------------
; Scan done
; -------------------------------------------------------------------
.scan_done:
    ; Capture bench end TSC
    cmp byte [bench_enabled], 0
    je .skip_bench_end
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [bench_end_tsc], rax
.skip_bench_end:
    call write_summary
    cmp byte [wait_secs], 0
    je .skip_wait
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rbx, rax
    movzx ecx, byte [wait_secs]
    mov rax, [tsc_hz]
    mul rcx
    add rax, rbx
    mov r12, rax
.wait_loop:
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r12
    jae .skip_wait
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 1000
    syscall
    test rax, rax
    jle .wait_loop
    call recv_and_classify
    jmp .wait_loop
.skip_wait:
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

; -------------------------------------------------------------------
; Entry points for special modes
; -------------------------------------------------------------------
.wizard_entry:
    mov byte [prompt_mode], 1
    call wizard_flow
    test eax, eax
    jnz .prompt_fail
    jmp .ports_ready

.prompt_fail:
    mov r12d, 1
    jmp .exit

.about_entry:
    call print_about
    xor r12d, r12d
    jmp .exit

.usage:
    mov rax, SYS_WRITE
    mov rdi, 2
    lea rsi, [usage_msg]
    mov rdx, usage_len
    syscall
    mov r12d, 1
    jmp .exit

.error:
    call flush_output
    mov rax, SYS_WRITE
    mov rdi, 2
    lea rsi, [error_msg]
    mov rdx, error_len
    syscall
    mov r12d, 1

.exit:
    call flush_output
    mov rax, [output_fd]
    test rax, rax
    jz .exit_no_out
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall
.exit_no_out:
    mov rax, [epoll_fd]
    test rax, rax
    jz .exit_close_raw
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_close_raw:
    mov rax, [send_fd]
    test rax, rax
    jz .exit_close_raw_fd
    cmp rax, [raw_fd]
    je .exit_close_raw_fd
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_close_raw_fd:
    mov rax, [raw_fd]
    test rax, rax
    jz .exit_now
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_now:
    mov rax, SYS_EXIT
    mov rdi, r12
    syscall

; ===========================================================================
; NetroX-ASM  |  Linux x86_64  |  Part 4 of 5: Output, summary, bench
; ===========================================================================

; -------------------------------------------------------------------
; buf_write  rsi=src, edx=len
; Buffered write to stdout (flush when near-full)
; -------------------------------------------------------------------
buf_write:
    mov r8, rsi
    mov r9d, edx
    mov rax, [output_pos]
    mov rcx, rax
    add rcx, r9
    cmp rcx, OUTPUT_BUF_SIZE
    ja .buf_flush
    cmp rcx, OUTPUT_FLUSH_THRESHOLD
    jae .buf_flush
.buf_write_inner:
    lea rdi, [output_buf+rax]
    mov rsi, r8
    mov rdx, r9
    mov rcx, rdx
    rep movsb
    add rax, r9
    mov [output_pos], rax
    ret
.buf_flush:
    call flush_output
    mov rax, [output_pos]
    jmp .buf_write_inner

flush_output:
    mov rax, [output_pos]
    test rax, rax
    jz .done
    mov rdi, 1
    lea rsi, [output_buf]
    mov rdx, rax
    mov rax, SYS_WRITE
    syscall
    mov rbx, [output_fd]
    test rbx, rbx
    jz .clear
    mov rdi, rbx
    lea rsi, [output_buf]
    mov rdx, [output_pos]
    mov rax, SYS_WRITE
    syscall
.clear:
    mov qword [output_pos], 0
.done:
    ret

; -------------------------------------------------------------------
; append_u16  ax=value
; Converts 16-bit value to ASCII and calls buf_write
; Uses multiply-by-reciprocal trick (no idiv)
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
; append_u32  eax=value
; -------------------------------------------------------------------
append_u32:
    mov eax, eax
    lea rsi, [out_buf+10]
    xor rcx, rcx
.digits32:
    xor edx, edx
    mov ebx, 10
    div ebx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    inc rcx
    test eax, eax
    jnz .digits32
    mov edx, ecx
    call buf_write
    ret

; -------------------------------------------------------------------
; append_ip  eax=ipv4
; -------------------------------------------------------------------
append_ip:
    push rbx
    mov ebx, eax
    movzx eax, bl
    call append_u16
    mov byte [out_buf], '.'
    lea rsi, [out_buf]
    mov edx, 1
    call buf_write
    mov eax, ebx
    shr eax, 8
    movzx eax, al
    call append_u16
    mov byte [out_buf], '.'
    lea rsi, [out_buf]
    mov edx, 1
    call buf_write
    mov eax, ebx
    shr eax, 16
    movzx eax, al
    call append_u16
    mov byte [out_buf], '.'
    lea rsi, [out_buf]
    mov edx, 1
    call buf_write
    mov eax, ebx
    shr eax, 24
    movzx eax, al
    call append_u16
    pop rbx
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
; Prints:  PORT OPEN TTL=N WIN=N[ OS=name]\n
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
    ; Optional OS fingerprint
    cmp byte [os_enabled], 0
    je .no_os
    lea rsi, [os_prefix_msg]
    mov edx, os_prefix_len
    call buf_write
    movzx eax, byte [os_result_idx]
    cmp eax, 6
    jbe .os_valid
    mov eax, 6
.os_valid:
    mov rsi, [os_str_ptrs + rax*8]
    ; measure length of null-terminated string
    xor edx, edx
.os_strlen:
    cmp byte [rsi+rdx], 0
    je .os_strlen_done
    inc edx
    jmp .os_strlen
.os_strlen_done:
    call buf_write
.no_os:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

; -------------------------------------------------------------------
; record_open  ecx=port
; Sets bit in result_map and increments open_count
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
; Prints open count and the list of open ports from result_map
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
    jz .summary_none

    lea rsi, [open_ports_msg]
    mov edx, open_ports_len
    call buf_write
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
.summary_loop:
    cmp ecx, r15d
    ja .summary_done
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    test byte [result_map+rax], r8b
    jz .summary_next
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
.summary_next:
    inc ecx
    jmp .summary_loop
.summary_done:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret
.summary_none:
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
; Prints benchmark stats after scan completes
; -------------------------------------------------------------------
write_bench:
    lea rsi, [bench_hdr_msg]
    mov edx, bench_hdr_len
    call buf_write

    ; Ports scanned
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

    ; Open ports found
    lea rsi, [bench_open_msg]
    mov edx, bench_open_len
    call buf_write
    mov ax, [open_count]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    ; Elapsed time in ms = (end_tsc - start_tsc) * 1000 / tsc_hz
    lea rsi, [bench_time_msg]
    mov edx, bench_time_len
    call buf_write
    mov rax, [bench_end_tsc]
    sub rax, [bench_start_tsc]
    mov rcx, 1000
    mul rcx
    mov rcx, [tsc_hz]
    test rcx, rcx
    jz .bench_no_time
    div rcx
    ; ax = elapsed ms (low 16 bits sufficient for most scans)
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
.bench_no_time:
    lea rsi, [bench_end_msg]
    mov edx, bench_end_len
    call buf_write
    ret

; -------------------------------------------------------------------
; print_about
; -------------------------------------------------------------------
print_about:
    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write
    lea rsi, [about_msg]
    mov edx, about_len
    call buf_write
    call flush_output
    ret

; -------------------------------------------------------------------
; is_about_mode  rdi=arg -> eax=1 if "--about"
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
    mov r8d, ecx
    call buf_write
    call flush_output
    mov rax, SYS_READ
    xor rdi, rdi
    mov rsi, rbx
    mov rdx, r8
    dec rdx
    syscall
    test rax, rax
    jle .empty
    mov rcx, rax
    mov byte [rbx+rcx], 0
    mov rdi, rbx
    call trim_line
    mov al, [rbx]
    test al, al
    setnz al
    movzx eax, al
    pop rbx
    ret
.empty:
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

    ; Question 8: interface
    lea rsi, [wiz_q_iface]
    mov edx, wiz_q_iface_len
    lea rdi, [input_buf]
    mov ecx, 256
    call prompt_read_line
    test eax, eax
    jz .iface_done
    lea rsi, [input_buf]
    call copy_iface_name
    mov byte [iface_set], 1
.iface_done:

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
    mov rax, SYS_READ
    xor rdi, rdi
    lea rsi, [input_buf]
    mov rdx, 1
    syscall
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

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 60
    xor r10, r10
    lea r8, [sockaddr_dst]
    mov r9, 16
    syscall

    mov byte [host_up_map], 0
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov rdx, 1
    mov r10, 2000
    syscall
    test rax, rax
    jle .print_down

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov rdx, 4096
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    test rax, rax
    js .print_down

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
; NetroX-ASM  |  Linux x86_64  |  Part 5 of 5: Network helpers, rate, stabilize
; ===========================================================================

; -------------------------------------------------------------------
; copy_iface_name  rsi=src  -> eax=0 ok, 1 too long
; Copies up to 15 bytes into iface_name
; -------------------------------------------------------------------
copy_iface_name:
    push rbx
    lea rdi, [iface_name]
    xor eax, eax
    mov rcx, 16
    rep stosb
    lea rdi, [iface_name]
    mov rcx, 15
.copy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ok
    inc rsi
    inc rdi
    dec rcx
    jnz .copy
    pop rbx
    mov eax, 1
    ret
.ok:
    pop rbx
    xor eax, eax
    ret

; -------------------------------------------------------------------
; setup_send_engine
; If --iface: use AF_PACKET + verify interface is up.
; Otherwise: reuse raw_fd for sending.
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
setup_send_engine:
    cmp byte [iface_set], 0
    je .use_raw
    call verify_iface
    test eax, eax
    jnz .fail
    mov rax, SYS_SOCKET
    mov rdi, AF_PACKET
    mov rsi, SOCK_DGRAM
    mov rdx, ETH_P_IP_BE
    syscall
    test rax, rax
    js .fail
    mov [send_fd], rax
    mov word [sockaddr_ll], AF_PACKET
    mov word [sockaddr_ll+2], ETH_P_IP_BE
    mov eax, [ifindex]
    mov [sockaddr_ll+4], eax
    mov byte [engine_id], ENGINE_L2
    xor eax, eax
    ret
.use_raw:
    mov rax, [raw_fd]
    mov [send_fd], rax
    xor eax, eax
    ret
.fail:
    mov eax, 1
    ret

; -------------------------------------------------------------------
; verify_iface
; Checks iface_name via SIOCGIFINDEX + SIOCGIFFLAGS
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
verify_iface:
    push rbx
    lea rdi, [ifreq_buf]
    xor eax, eax
    mov rcx, 5
    rep stosq
    lea rsi, [iface_name]
    lea rdi, [ifreq_buf]
    mov rcx, 16
.copy_ifr:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ifr_copied
    inc rsi
    inc rdi
    dec rcx
    jnz .copy_ifr
    jmp .fail_pop

.ifr_copied:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .fail_pop
    mov rbx, rax

    mov rax, SYS_IOCTL
    mov rdi, rbx
    mov rsi, SIOCGIFINDEX
    lea rdx, [ifreq_buf]
    syscall
    test rax, rax
    js .fail_close
    mov eax, [ifreq_buf+16]
    mov [ifindex], eax

    mov rax, SYS_IOCTL
    mov rdi, rbx
    mov rsi, SIOCGIFFLAGS
    lea rdx, [ifreq_buf]
    syscall
    test rax, rax
    js .fail_close
    mov ax, [ifreq_buf+16]
    test ax, IFF_UP
    jz .fail_close
    test ax, IFF_RUNNING
    jz .fail_close

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rbx
    xor eax, eax
    ret

.fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fail_pop:
    pop rbx
    mov eax, 1
    ret

; -------------------------------------------------------------------
; get_local_ip
; Opens a UDP socket, connects to target IP (port 53),
; reads back our local IP via getsockname
; Returns eax=0 ok, 1 fail
; -------------------------------------------------------------------
get_local_ip:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .fail
    mov rbx, rax

    mov word  [sockaddr_tmp],   AF_INET
    mov word  [sockaddr_tmp+2], 0x3500      ; port 53 big-endian
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    mov rax, SYS_CONNECT
    mov rdi, rbx
    lea rsi, [sockaddr_tmp]
    mov rdx, 16
    syscall
    test rax, rax
    js .fail_close

    mov dword [addrlen], 16
    mov rax, SYS_GETSOCKNAME
    mov rdi, rbx
    lea rsi, [sockaddr_local]
    lea rdx, [addrlen]
    syscall
    test rax, rax
    js .fail_close

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    xor eax, eax
    ret

.fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fail:
    mov eax, 1
    ret

; -------------------------------------------------------------------
; intelligence_gate  - calls rate_gate (and future hooks)
; -------------------------------------------------------------------
intelligence_gate:
    call rate_gate
    ret

; -------------------------------------------------------------------
; rate_gate  - RDTSC-based packet rate limiter
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
; Input:  ecx = destination port (port we probed)
;         edx = ack number from received SYN-ACK
; Output: ZF=1 if valid response, ZF=0 if invalid
; -------------------------------------------------------------------
cookie_verify:
    push rax
    call cookie_generate
    inc  eax
    cmp  edx, eax
    pop  rax
    ret

; -------------------------------------------------------------------
; index_to_ip_port
; Input:  rax = scan index
; Output: ecx = port, [current_scan_ip] set
; -------------------------------------------------------------------
index_to_ip_port:
    push rbx
    push rdx
    push rsi
    push r8
    push r9

    ; port_count
    movzx rbx, word [end_port]
    movzx rcx, word [start_port]
    sub  rbx, rcx
    inc  rbx
    cmp byte [port_list_mode], 0
    je .check_top_ports
    movzx rbx, word [port_list_count]
    jmp .port_count_set
.check_top_ports:
    cmp byte [top_ports_mode], 0
    je .port_count_set
    movzx rbx, word [top_ports_n]
.port_count_set:

    xor  rdx, rdx
    div  rbx                    ; rax = ip_idx, rdx = port_idx
    push rdx

    xor  r8d, r8d
    xor  r9d, r9d
.range_loop:
    cmp  r9d, [ip_range_count]
    jae  .range_done
    lea  rsi, [ip_ranges + r9*8]
    mov  ecx, [rsi+4]
    add  ecx, r8d
    cmp  eax, r8d
    jb   .range_done
    cmp  eax, ecx
    jb   .found_range
    mov  r8d, ecx
    inc  r9d
    jmp  .range_loop
.found_range:
    mov  ecx, [rsi]
    sub  eax, r8d
    add  ecx, eax
    mov  [current_scan_ip], ecx
.range_done:

    pop  rdx
    cmp byte [port_list_mode], 0
    je .check_top_ports2
    movzx ecx, word [port_list_buf + rdx*2]
    jmp .done
.check_top_ports2:
    cmp byte [top_ports_mode], 0
    je .range_port
    mov rsi, [top_ports_ptr]
    movzx ecx, word [rsi + rdx*2]
    jmp .done
.range_port:
    movzx ecx, word [start_port]
    add  ecx, edx
.done:
    pop  r9
    pop  r8
    pop  rsi
    pop  rdx
    pop  rbx
    ret

; -------------------------------------------------------------------
; write_cstr  rsi=string
; -------------------------------------------------------------------
write_cstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .done
    inc edx
    jmp .len
.done:
    call buf_write
    ret

; -------------------------------------------------------------------
; scan_mode_name  al=scan_mode, returns rsi=ptr
; -------------------------------------------------------------------
scan_mode_name:
    cmp al, SCAN_SYN
    je .syn
    cmp al, SCAN_ACK
    je .ack
    cmp al, SCAN_FIN
    je .fin
    cmp al, SCAN_NULL
    je .null
    cmp al, SCAN_XMAS
    je .xmas
    cmp al, SCAN_WINDOW
    je .window
    cmp al, SCAN_MAIMON
    je .maimon
    cmp al, SCAN_UDP
    je .udp
    cmp al, SCAN_PING
    je .ping
    cmp al, SCAN_SAR
    je .sar
    cmp al, SCAN_KIS
    je .kis
    cmp al, SCAN_PHANTOM
    je .phantom
    cmp al, SCAN_CALLBACK
    je .callback
    lea rsi, [scan_syn_str]
    ret
.syn:      lea rsi, [scan_syn_str]      ; fallthrough
    ret
.ack:      lea rsi, [scan_ack_str]
    ret
.fin:      lea rsi, [scan_fin_str]
    ret
.null:     lea rsi, [scan_null_str]
    ret
.xmas:     lea rsi, [scan_xmas_str]
    ret
.window:   lea rsi, [scan_window_str]
    ret
.maimon:   lea rsi, [scan_maimon_str]
    ret
.udp:      lea rsi, [scan_udp_str]
    ret
.ping:     lea rsi, [scan_ping_str]
    ret
.sar:      lea rsi, [scan_sar_str]
    ret
.kis:      lea rsi, [scan_kis_str]
    ret
.phantom:  lea rsi, [scan_phantom_str]
    ret
.callback: lea rsi, [scan_callback_str]
    ret

; -------------------------------------------------------------------
; setup_sigint_handler
; -------------------------------------------------------------------
setup_sigint_handler:
    sub  rsp, 152
    lea  rax, [sigint_handler]
    mov  [rsp], rax
    mov  qword [rsp+8], 0
    mov  qword [rsp+16], 0
    mov  rax, SYS_RT_SIGACTION
    mov  rdi, SIGINT
    mov  rsi, rsp
    xor  rdx, rdx
    mov  r10, 8
    syscall
    add  rsp, 152
    ret

; -------------------------------------------------------------------
; sigint_handler
; -------------------------------------------------------------------
sigint_handler:
    call write_resume_file
    lea  rsi, [resume_msg]
    call write_cstr
    call flush_output
    mov  rax, SYS_EXIT
    xor  rdi, rdi
    syscall
    ret

; -------------------------------------------------------------------
; write_resume_file
; -------------------------------------------------------------------
write_resume_file:
    mov  rax, SYS_OPEN
    lea  rdi, [resume_fname]
    mov  rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov  rdx, 0644
    syscall
    test rax, rax
    js   .done
    mov  [resume_fd], rax
    mov  qword [output_pos], 0
    lea  rsi, [resume_idx_key]
    call write_cstr
    mov  eax, dword [resume_index]
    call append_u32
    lea  rsi, [resume_nl]
    call write_cstr
    lea  rsi, [resume_target_key]
    call write_cstr
    mov  eax, [target_ip]
    call append_ip
    lea  rsi, [resume_nl]
    call write_cstr
    lea  rsi, [resume_ports_key]
    call write_cstr
    movzx ax, word [start_port]
    call append_u16
    mov  byte [out_buf], '-'
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write
    movzx ax, word [end_port]
    call append_u16
    lea  rsi, [resume_nl]
    call write_cstr
    lea  rsi, [resume_rate_key]
    call write_cstr
    mov  eax, [rate_value]
    call append_u32
    lea  rsi, [resume_nl]
    call write_cstr
    lea  rsi, [resume_scan_key]
    call write_cstr
    mov  al, [scan_mode]
    call scan_mode_name
    call write_cstr
    lea  rsi, [resume_nl]
    call write_cstr

    mov  rax, SYS_WRITE
    mov  rdi, [resume_fd]
    lea  rsi, [output_buf]
    mov  rdx, [output_pos]
    syscall
    mov  rax, SYS_CLOSE
    mov  rdi, [resume_fd]
    syscall
    mov  qword [output_pos], 0
.done:
    ret

; -------------------------------------------------------------------
; read_resume_file
; -------------------------------------------------------------------
read_resume_file:
    mov  rax, SYS_OPEN
    lea  rdi, [resume_fname]
    xor  rsi, rsi
    syscall
    test rax, rax
    js   .done
    mov  rbx, rax
    mov  rax, SYS_READ
    mov  rdi, rbx
    lea  rsi, [config_buf]
    mov  rdx, 4096
    syscall
    test rax, rax
    jle  .close
    lea  rsi, [config_buf]
.line_loop:
    cmp  byte [rsi], 0
    je   .close
    mov  rdi, rsi
    ; find '='
.find_eq:
    mov  al, [rdi]
    test al, al
    jz   .next_line
    cmp  al, '='
    je   .got_eq
    inc  rdi
    jmp  .find_eq
.got_eq:
    mov  byte [rdi], 0
    lea  rdi, [rsi]
    cmp  dword [rdi], 'resu'
    jne  .next_line
    cmp  dword [rdi+4], 'me-i'
    jne  .next_line
    cmp  dword [rdi+8], 'ndex'
    jne  .next_line
    lea  rdi, [rdi+12]
    ; skip spaces
.skip_space:
    cmp byte [rdi], ' '
    jne .parse_val
    inc rdi
    jmp .skip_space
.parse_val:
    call parse_u32
    mov  [resume_index], rax
    mov  byte [resume_flag], 1
.next_line:
    ; advance to next line
    mov  rdi, rsi
.find_nl:
    mov  al, [rdi]
    test al, al
    jz   .close
    cmp  al, 10
    je   .line_adv
    inc  rdi
    jmp  .find_nl
.line_adv:
    inc  rdi
    mov  rsi, rdi
    jmp  .line_loop
.close:
    mov  rax, SYS_CLOSE
    mov  rdi, rbx
    syscall
.done:
    ret

; -------------------------------------------------------------------
; load_config_file
; -------------------------------------------------------------------
load_config_file:
    mov  rax, SYS_OPEN
    lea  rdi, [config_filename]
    xor  rsi, rsi
    syscall
    test rax, rax
    js   .done
    mov  rbx, rax
    mov  rax, SYS_READ
    mov  rdi, rbx
    lea  rsi, [config_buf]
    mov  rdx, 4096
    syscall
    test rax, rax
    jle  .close
    lea  rsi, [config_buf]
.cfg_loop:
    mov  al, [rsi]
    test al, al
    jz   .close
    cmp  al, '#'
    je   .skip_line
    mov  rdi, rsi
.find_eq2:
    mov  al, [rdi]
    test al, al
    jz   .skip_line
    cmp  al, '='
    je   .cfg_eq
    inc  rdi
    jmp  .find_eq2
.cfg_eq:
    mov  byte [rdi], 0
    lea  rdi, [rsi]
    lea  r8, [rdi]
    lea  rdi, [rsi]
    ; scan key
    cmp  dword [rdi], 'scan'
    jne  .chk_rate
    lea  rdi, [r8+5]
    call parse_scan_mode
    test al, al
    jz   .skip_line
    mov  [scan_mode], al
    jmp  .skip_line
.chk_rate:
    cmp  dword [rdi], 'rate'
    jne  .chk_ports
    lea  rdi, [r8+5]
    call parse_u32
    test eax, eax
    jz   .skip_line
    mov  [rate_value], eax
    jmp  .skip_line
.chk_ports:
    cmp  dword [rdi], 'port'
    jne  .skip_line
    lea  rdi, [r8+6]
    call parse_port_range
    test ax, ax
    jz   .skip_line
    mov  [start_port], ax
    mov  [end_port], dx
.skip_line:
    ; advance to next line
    mov  rdi, rsi
.find_nl2:
    mov  al, [rdi]
    test al, al
    jz   .close
    cmp  al, 10
    je   .line_adv2
    inc  rdi
    jmp  .find_nl2
.line_adv2:
    inc  rdi
    mov  rsi, rdi
    jmp  .cfg_loop
.close:
    mov  rax, SYS_CLOSE
    mov  rdi, rbx
    syscall
.done:
    ret

; -------------------------------------------------------------------
; print_echo_config
; -------------------------------------------------------------------
print_echo_config:
    lea  rsi, [echo_hdr_msg]
    call write_cstr
    lea  rsi, [echo_target_msg]
    call write_cstr
    mov  eax, [target_ip]
    call append_ip
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    lea  rsi, [echo_scan_msg]
    call write_cstr
    mov  al, [scan_mode]
    call scan_mode_name
    call write_cstr
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    lea  rsi, [echo_ports_msg]
    call write_cstr
    movzx ax, word [start_port]
    call append_u16
    mov  byte [out_buf], '-'
    lea  rsi, [out_buf]
    mov  edx, 1
    call buf_write
    movzx ax, word [end_port]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    lea  rsi, [echo_rate_msg]
    call write_cstr
    mov  eax, [rate_value]
    call append_u32
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    lea  rsi, [echo_engine_msg]
    call write_cstr
    movzx eax, byte [engine_mode]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    lea  rsi, [echo_timing_msg]
    call write_cstr
    movzx eax, byte [timing_level]
    call append_u16
    lea  rsi, [newline_msg]
    mov  edx, newline_len
    call buf_write
    call flush_output
    mov  rax, SYS_EXIT
    xor  rdi, rdi
    syscall

; -------------------------------------------------------------------
; random_hosts_init
; -------------------------------------------------------------------
random_hosts_init:
    mov byte [cidr_mode], 1
    mov dword [ip_range_count], 0
    mov qword [total_ip_count], 0
    mov ecx, [random_host_count]
    test ecx, ecx
    jz .done
.gen_loop:
    call xorshift64_next
    mov eax, eax
    mov bl, al                    ; a
    mov bh, ah                    ; b
    cmp bl, 10
    je .gen_loop
    cmp bl, 127
    je .gen_loop
    cmp bl, 0
    je .gen_loop
    cmp bl, 224
    jae .gen_loop
    cmp bl, 172
    jne .chk_192
    movzx edx, bh
    cmp edx, 16
    jb .chk_192
    cmp edx, 31
    jbe .gen_loop
.chk_192:
    cmp bl, 192
    jne .chk_ff
    cmp bh, 168
    je .gen_loop
.chk_ff:
    cmp eax, 0xFFFFFFFF
    je .gen_loop
    mov edx, [ip_range_count]
    cmp edx, MAX_IP_RANGES
    jae .done
    lea rsi, [ip_ranges + rdx*8]
    mov [rsi], eax
    mov dword [rsi+4], 1
    cmp dword [ip_range_count], 0
    jne .count_up
    mov [target_ip], eax
    mov [current_scan_ip], eax
.count_up:
    inc dword [ip_range_count]
    mov rbx, [total_ip_count]
    inc rbx
    mov [total_ip_count], rbx
    loop .gen_loop
.done:
    ret

; -------------------------------------------------------------------
; stabilize_step
; Adaptive rate control: slow down if too many timeouts,
; speed up if too many confirmed responses
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
    mov dword [stab_sent],   0
    mov dword [stab_recv],   0
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
; Reads rate_value, calibrates TSC, sets rate_cycles
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
    shr rax, 2
    mov [rate_min_cycles], rax
.done:
    ret

; -------------------------------------------------------------------
; calibrate_tsc
; Measures TSC frequency using clock_gettime(CLOCK_MONOTONIC)
; Waits ~50ms, counts TSC ticks, computes tsc_hz
; -------------------------------------------------------------------
calibrate_tsc:
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    lea rsi, [ts_start]
    syscall
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [tsc_start], rax
.loop:
    mov rax, SYS_CLOCK_GETTIME
    mov rdi, CLOCK_MONOTONIC
    lea rsi, [ts_end]
    syscall
    mov rax, [ts_end]
    mov r10, [ts_start]
    sub rax, r10
    mov rcx, [ts_end+8]
    sub rcx, [ts_start+8]
    jns .delta_ok
    dec rax
    add rcx, 1000000000
.delta_ok:
    mov r11, 1000000000
    imul rax, r11
    add rax, rcx
    cmp rax, 50000000           ; wait at least 50ms
    jb .loop
    mov r8, rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r9, rax
    sub rax, [tsc_start]
    mov rcx, 1000000000
    mul rcx
    div r8
    mov [tsc_hz], rax
    ret

; -------------------------------------------------------------------
; blackrock_init
; -------------------------------------------------------------------
blackrock_init:
    rdtsc
    shl rdx, 32
    or rax, rdx                     ; 64-bit seed from TSC
    ; Derive 6 round keys via xorshift64
    mov r8, rax
    mov rcx, 6
    lea rdi, [blackrock_key_0]
.keygen:
    ; xorshift64
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
    add rax, r10                    ; R + key
    ; Bit mixing: multiply by a prime, rotate, XOR
    mov rcx, 0x9e3779b97f4a7c15     ; golden ratio constant
    mul rcx
    xor rax, rdx                    ; fold high bits down
    rol rax, 17                     ; rotate
    ret

; -------------------------------------------------------------------
; blackrock_permute
; -------------------------------------------------------------------
blackrock_permute:
    push rbx
    push r12
    push r13

    ; Compute split: a_bits = floor(log2(range) / 2)
    ;                b_bits = ceil(log2(range) / 2)
    ; For 16-bit range (65535 elements): a_bits=8, b_bits=8
    ; For larger ranges: adjust accordingly
    mov r12, rdi                    ; index to permute
    mov r13, rsi                    ; range

    ; Compute half-sizes for Feistel
    ; a = lower half bits, b = upper half bits
    ; For simplicity with 16-bit range:
    ;   a_mask = 0x00FF (lower 8 bits)
    ;   b_mask = 0xFF00 (upper 8 bits)
    ;   a = index & 0xFF
    ;   b = (index >> 8) & 0xFF

    ; For arbitrary ranges: use dynamic bit splitting
    ; (hardcode for 16-bit range as optimization)
    mov rbx, r12
    and rbx, 0xFF                   ; L = lower 8 bits
    mov rcx, r12
    shr rcx, 8
    and rcx, 0xFF                   ; R = upper 8 bits

    ; 6 Feistel rounds
    %assign round 0
    %rep 6
        mov r9, rcx                 ; R
        mov r10, [blackrock_key_ %+ round]
        call feistel_f              ; rax = f(R, key)
        xor rbx, rax                ; L = L XOR f(R, key)
        and rbx, 0xFF               ; keep in range
        ; Ensure result stays within range using cycle-walking:
        ; if result >= range_half: xor again with adjusted key
        ; (for simplicity with power-of-2 ranges, mask is sufficient)
        xchg rbx, rcx               ; swap L,R for next round
        %assign round round+1
    %endrep

    ; Reconstruct: output = (L << 8) | R
    shl rcx, 8
    or rcx, rbx
    ; Cycle-walking: if result >= range, permute again
.cycle_walk:
    cmp rcx, r13
    jb .done
    ; Re-permute the out-of-range result
    mov r12, rcx
    ; (simplified: just increment and mask for speed)
    ; Full implementation: recursive permute until in range
    inc rcx
    cmp rcx, r13
    jb .done
    xor rcx, rcx                    ; wrap to 0
.done:
    mov rax, rcx
    pop r13
    pop r12
    pop rbx
    ret

; -------------------------------------------------------------------
; incremental_ip_cksum_update
; -------------------------------------------------------------------
incremental_ip_cksum_update:
    movzx eax, word [packet_buf+10] ; old checksum
    not ax                          ; ~old_checksum
    movzx ebx, word [packet_buf+4]  ; new IP ID
    dec bx                          ; old IP ID = new - 1
    not bx                          ; ~old_value
    add ax, bx                      ; ~old_checksum + ~old_value
    ; fold carry
    mov cx, ax
    shr cx, 15
    and ax, 0x7FFF
    add ax, cx
    movzx ebx, word [packet_buf+4]  ; new IP ID
    add ax, bx                      ; + new_value
    not ax                          ; ~ result
    mov [packet_buf+10], ax         ; store new checksum
    ret

; -------------------------------------------------------------------
; incremental_tcp_cksum_update
; -------------------------------------------------------------------
incremental_tcp_cksum_update:
    movzx eax, word [packet_buf+36] ; old TCP checksum
    not ax
    movzx ebx, word [packet_buf+22] ; new dst_port
    sub bx, 1                       ; approximate old port (if sequential)
    ; NOTE: for non-sequential (Blackrock) iteration, must store old port
    not bx
    add ax, bx
    movzx ebx, word [packet_buf+22]
    add ax, bx
    not ax
    mov [packet_buf+36], ax
    ret

; -------------------------------------------------------------------
; fast_cksum_update
; -------------------------------------------------------------------
fast_cksum_update:
    call incremental_ip_cksum_update
    call incremental_tcp_cksum_update
    ret

; -------------------------------------------------------------------
; init_packet_sse2
; -------------------------------------------------------------------
init_packet_sse2:
    movdqu xmm0, [pkt_template_0]
    movdqu [packet_buf],    xmm0    ; bytes 0-15
    movdqu xmm1, [pkt_template_1]
    movdqu [packet_buf+16], xmm1    ; bytes 16-31
    movdqu xmm2, [pkt_template_2]
    movdqu [packet_buf+24], xmm2    ; bytes 24-39 (overlapping is fine)
    ; Now patch: src IP, dst IP, src port
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax
    mov ax,  [src_port_be]
    mov [packet_buf+20], ax
    ret

; -------------------------------------------------------------------
; xorshift64_next
; -------------------------------------------------------------------
xorshift64_next:
    mov rax, [xorshift_state]
    mov rcx, rax
    shl rcx, 13
    xor rax, rcx
    mov rcx, rax
    shr rcx, 7
    xor rax, rcx
    mov rcx, rax
    shl rcx, 17
    xor rax, rcx
    mov [xorshift_state], rax
    ; lower 32 bits = usable random value
    ret

; -------------------------------------------------------------------
; rate_gate_v2
; -------------------------------------------------------------------
rate_gate_v2:
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
    sub r9, r8                      ; elapsed cycles
    cmp r9, [rate_cycles]
    jae .store
    ; Check if remaining wait is large (>10000 cycles ~ few microseconds)
    mov r10, [rate_cycles]
    sub r10, r9                     ; remaining cycles
    cmp r10, 10000
    jb .spin_tight                  ; small wait: pure spin
    pause                           ; PAUSE hint: reduces power + memory hazards
.spin_tight:
    rdtsc
    shl rdx, 32
    or rax, rdx
    jmp .wait
.store:
    mov [last_send_tsc], rax
.done:
    ret

; -------------------------------------------------------------------
; update_rate_cycles
; -------------------------------------------------------------------
update_rate_cycles:
    mov ecx, [rate_value]
    test ecx, ecx
    jz .done
    mov rax, [tsc_hz]
    xor rdx, rdx
    div rcx
    mov [rate_cycles], rax
.done:
    ret
