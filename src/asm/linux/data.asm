; ============================================================
; NetroX-ASM Hybrid | Linux hot-path data (WIP extraction)
; ============================================================
%ifndef DATA_LINUX_ASM
%define DATA_LINUX_ASM 1

SECTION .data
; Keep per-engine tables used in hot-path
; Engine strings (used by ASM engines)
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
    dw 1200,2500,  40, 120, KIS_SVC_HEAVY,    65
    times 13 db 0
    dw 2500,9999,  50, 500, KIS_SVC_VIRT,     60
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

SECTION .bss
; Hot-path buffers and state referenced by scan_core
packet_buf      resb 2048
recv_buf        resb 4096
epoll_out       resb 64

sockaddr_dst    resb 16
sockaddr_ll     resb 32

send_fd         resq 1
iface_set       resb 1
iface_name      resb 16
ifreq_buf       resb 40
ifindex         resd 1

dst_port        resw 1
dst_port_be     resw 1
src_port_be     resw 1
src_port        resw 1

target_ip       resd 1
scan_mode       resb 1
cidr_mode       resb 1
os_enabled      resb 1
engine_id       resb 1

batch_counter   resb 1

retry_cur       resb 1
retry_max       resb 1

filtered_count  resd 1
closed_count    resd 1

stab_enabled    resb 1
stab_sent       resd 1
stab_recv       resd 1
stab_timeout    resd 1

last_ttl        resb 1
last_win        resw 1
last_rtt_ns     resd 1

resume_index    resq 1
host_up_map     resb 1
source_ip       resd 1
sockaddr_tmp    resb 16
sockaddr_local  resb 16
addrlen         resd 1

%endif
