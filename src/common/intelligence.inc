; ============================================================
; intelligence.inc  -  NetroX-ASM Intelligence Engine
;
; Provides:
;   intel_init          - zero all intel state (call once before scan)
;   intel_analyze       - full passive analysis from a SYN-ACK in recv_buf
;   intel_score         - compute final OS score from all collected fields
;   intel_rtt_record    - store RTT for current port (call after each recv)
;   intel_ipid_record   - track IP ID field for zombie / LB detection
;   intel_lb_check      - detect load balancer from repeated probes
;   intel_banner_match  - match recv_buf against service signatures
;   intel_print_record  - print full intel line for one open port
;   intel_print_rtt_map - print RTT outlier report after scan
;
; Depends on (must be declared in .bss before %include):
;   last_ttl    resb 1      - populated by scan loop from recv_buf+8
;   last_win    resw 1      - populated by scan loop from TCP header+14
;   recv_buf    resb 4096   - full received packet
;   target_ip   resd 1
;   tsc_hz      resq 1
;   output_pos  resq 1      (via buf_write / flush_output)
;
; Caller must %include this file AFTER declaring the .bss section
; and AFTER checksum.inc / packet.inc / engine.inc.
; ============================================================

%ifndef INTELLIGENCE_INC
%define INTELLIGENCE_INC 1

; ============================================================
; OS ID constants
; ============================================================
%define OS_LINUX_6      0
%define OS_LINUX_4      1
%define OS_WINDOWS_10   2
%define OS_WINDOWS_7    3
%define OS_MACOS        4
%define OS_NETDEV       5
%define OS_UNKNOWN      6
%define OS_COUNT        7

; ============================================================
; IP ID class constants
; ============================================================
%define IPID_UNKNOWN        0
%define IPID_ZERO           1
%define IPID_INCREMENTAL    2
%define IPID_RANDOM         3
%define IPID_CONSTANT       4

; ============================================================
; Service ID constants
; ============================================================
%define SVC_UNKNOWN     0
%define SVC_SSH         1
%define SVC_SSH_OLD     2
%define SVC_FTP_SMTP    3
%define SVC_HTTP        4
%define SVC_TLS         5
%define SVC_REDIS_OPEN  6
%define SVC_POP3        7
%define SVC_IMAP        8
%define SVC_VNC         9
%define SVC_TELNET      10
%define SVC_MYSQL       11
%define SVC_REDIS_AUTH  12

; ============================================================
; Score weights  (max possible = 145)
; ============================================================
%define SCORE_WINDOW        25
%define SCORE_TTL           20
%define SCORE_MSS           15
%define SCORE_OPT_ORDER     20
%define SCORE_WSCALE        10
%define SCORE_SACK           5
%define SCORE_TS             5
%define SCORE_DF             5
%define SCORE_IPID          10
%define SCORE_PROBE         30

; Confidence thresholds
%define CONF_HIGH   120
%define CONF_MED     80
%define CONF_LOW     40

; ============================================================
; RTT table size  (one 32-bit entry per port 1-65535)
; ============================================================
%define RTT_TABLE_SIZE  65535

; ============================================================
; IP ID ring size for zombie / LB detection
; ============================================================
%define IPID_RING_SIZE  6
%define LB_RING_SIZE    5

; ============================================================
; Banner signature entry size  (32 bytes)
; ============================================================
%define SIG_ENTRY_SIZE  32

; ============================================================
; .bss additions  -  paste these into your .bss section
; BEFORE the %include of this file.
;
;   intel_rtt_table     resd RTT_TABLE_SIZE
;   intel_ipid_ring     resw IPID_RING_SIZE
;   intel_ipid_idx      resb 1
;   intel_lb_ttl        resb LB_RING_SIZE
;   intel_lb_win        resw LB_RING_SIZE
;   intel_lb_ts         resd LB_RING_SIZE
;   intel_lb_opthash    resd LB_RING_SIZE
;   intel_lb_idx        resb 1
;   intel_rtt_before    resq 1
;   intel_fp_ttl        resb 1
;   intel_fp_win        resw 1
;   intel_fp_mss        resw 1
;   intel_fp_wscale     resb 1
;   intel_fp_sack       resb 1
;   intel_fp_ts         resb 1
;   intel_fp_ts_val     resd 1
;   intel_fp_df         resb 1
;   intel_fp_ipid_class resb 1
;   intel_fp_opthash    resd 1
;   intel_fp_scores     resb OS_COUNT
;   intel_fp_best_idx   resb 1
;   intel_fp_best_score resb 1
;   intel_svc_id        resb 1
;   intel_svc_name      resb 16
;   intel_banner        resb 64
;   intel_banner_len    resw 1
;   intel_port_cur      resw 1
; ============================================================

; ============================================================
; .rodata  -  OS fingerprint table
; Each entry: [win_lo:2][win_hi:2][ttl_class:1][mss_lo:2][mss_hi:2]
;             [wscale:1][sack:1][ts:1][df:1][os_id:1][pad:2]
; ttl_class: 0=Linux/Unix(64), 1=Windows(128), 2=Device(255)
; mss range: [lo..hi] inclusive
; ============================================================
SECTION .rodata

intel_os_db:
    ; Linux 6.x / 5.x  win=64240  ttl=64  mss=1460  wscale=7  sack=1  ts=1  df=1
    dw 64240, 64240   ; win range
    db 0              ; ttl_class = Linux
    dw 1460, 1460     ; mss range
    db 7              ; wscale
    db 1              ; sack
    db 1              ; ts
    db 1              ; df
    db OS_LINUX_6     ; os_id
    dw 0              ; pad

    ; Linux 4.x        win=29200  ttl=64  mss=1460  wscale=7  sack=1  ts=1  df=1
    dw 29200, 29200
    db 0
    dw 1460, 1460
    db 7
    db 1
    db 1
    db 1
    db OS_LINUX_4
    dw 0

    ; Windows 10/11    win=65535 or 64240  ttl=128  mss=1460  wscale=8  sack=1  ts=0  df=1
    dw 64240, 65535
    db 1              ; ttl_class = Windows
    dw 1460, 1460
    db 8
    db 1
    db 0
    db 1
    db OS_WINDOWS_10
    dw 0

    ; Windows 7/8      win=8192-16384  ttl=128  mss=1460  wscale=2-8  sack=1  ts=0
    dw 8192, 16384
    db 1
    dw 1460, 1460
    db 2
    db 1
    db 0
    db 0
    db OS_WINDOWS_7
    dw 0

    ; macOS / BSD      win=65228 or 65535  ttl=64  mss=1460  wscale=6  sack=1  ts=1  df=1
    dw 65228, 65535
    db 0
    dw 1460, 1460
    db 6
    db 1
    db 1
    db 1
    db OS_MACOS
    dw 0

    ; Network device   win=4096-8192  ttl=255  mss=512-1460  wscale=0
    dw 4096, 8192
    db 2              ; ttl_class = Device
    dw 512, 1460
    db 0
    db 0
    db 0
    db 0
    db OS_NETDEV
    dw 0

intel_os_db_count equ ($ - intel_os_db) / 16

; ============================================================
; OS name strings
; ============================================================
intel_os_names:
    intel_os_name_0  db "Linux-5.x/6.x",  0
    intel_os_name_1  db "Linux-3.x/4.x",  0
    intel_os_name_2  db "Windows-10/11",   0
    intel_os_name_3  db "Windows-7/8",     0
    intel_os_name_4  db "macOS/BSD",        0
    intel_os_name_5  db "Network-Device",   0
    intel_os_name_6  db "Unknown",           0

intel_os_name_ptrs:
    dq intel_os_name_0
    dq intel_os_name_1
    dq intel_os_name_2
    dq intel_os_name_3
    dq intel_os_name_4
    dq intel_os_name_5
    dq intel_os_name_6

; ============================================================
; Confidence label strings
; ============================================================
intel_conf_high  db "(high)",   0
intel_conf_med   db "(likely)", 0
intel_conf_low   db "(maybe)",  0
intel_conf_unk   db "(unknown)",0

; ============================================================
; Banner signature table
; Entry layout (32 bytes):
;   [offset:1][length:1][pattern:16][svc_id:1][svc_name:13]
; offset  = byte offset in banner where pattern starts
; length  = number of bytes to compare
; svc_id  = SVC_xxx constant
; svc_name = null-terminated display name (13 bytes max)
; Terminator: length == 0
; ============================================================
intel_banner_db:
    ;      off len  pattern (16 bytes, null-padded)              svc_id    name (13 bytes)
    db 0,  7,  "SSH-2.0",  0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_SSH,       "SSH",        0,0,0,0,0,0,0,0,0,0
    db 0,  6,  "SSH-1.",   0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_SSH_OLD,   "SSH-OLD",    0,0,0,0,0,0
    db 0,  4,  "220 ",     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_FTP_SMTP,  "FTP-SMTP",   0,0,0,0
    db 0,  5,  "HTTP/",    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_HTTP,      "HTTP",       0,0,0,0,0,0,0,0
    db 0,  2,  0x16, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_TLS,       "TLS",        0,0,0,0,0,0,0,0,0
    db 0,  6,  "+PONG",  0x0D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_REDIS_OPEN, "Redis(noauth)", 0
    db 0,  4,  "+OK ",    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_POP3,      "POP3",       0,0,0,0,0,0,0,0
    db 0,  5,  "* OK ",   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_IMAP,      "IMAP",       0,0,0,0,0,0,0,0
    db 0,  4,  "RFB ",    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_VNC,       "VNC",        0,0,0,0,0,0,0,0,0
    db 0,  2,  0xFF, 0xFB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_TELNET,    "Telnet",     0,0,0,0,0,0
    db 0,  5,  0x4A, 0x00, 0x00, 0x00, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  SVC_MYSQL, "MySQL",  0,0,0,0,0,0,0,0
    db 0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; terminator

; ============================================================
; Output label strings
; ============================================================
intel_lbl_port   db "PORT  ", 0
intel_lbl_ttl    db " TTL=",  0
intel_lbl_hops   db " HOP=",  0
intel_lbl_win    db " WIN=",  0
intel_lbl_mss    db " MSS=",  0
intel_lbl_os     db " OS=",   0
intel_lbl_rtt    db " RTT=",  0
intel_lbl_svc    db " SVC=",  0
intel_lbl_us     db "us",     0
intel_lbl_ms     db "ms",     0
intel_lbl_sack   db " SACK",  0
intel_lbl_ts     db " TS",    0
intel_lbl_df     db " DF",    0
intel_lbl_zombie db " [ZOMBIE-CANDIDATE]", 0
intel_lbl_lb     db " [LOAD-BALANCER?]",   0
intel_lbl_newline db 10, 0
intel_rtt_hdr    db 10, "--- RTT OUTLIERS ---", 10, 0
intel_rtt_slow   db " SLOW",  0

; ============================================================
; SECTION .text begins here
; All routines below
; ============================================================
SECTION .text

; ------------------------------------------------------------
; intel_init
; Zero all intelligence state. Call once before scan loop.
; ------------------------------------------------------------
intel_init:
    push rdi
    push rcx

    ; Zero rtt table
    lea  rdi, [intel_rtt_table]
    xor  eax, eax
    mov  ecx, RTT_TABLE_SIZE
    rep  stosd

    ; Zero IP ID ring
    lea  rdi, [intel_ipid_ring]
    mov  ecx, IPID_RING_SIZE
    rep  stosw

    ; Zero LB rings
    lea  rdi, [intel_lb_ttl]
    mov  ecx, LB_RING_SIZE
    rep  stosb
    lea  rdi, [intel_lb_win]
    mov  ecx, LB_RING_SIZE
    rep  stosw
    lea  rdi, [intel_lb_ts]
    mov  ecx, LB_RING_SIZE
    rep  stosd
    lea  rdi, [intel_lb_opthash]
    mov  ecx, LB_RING_SIZE
    rep  stosd

    ; Zero all single-byte/word/dword intel fields
    mov  byte [intel_ipid_idx],      0
    mov  byte [intel_lb_idx],        0
    mov  qword [intel_rtt_before],   0
    mov  byte [intel_fp_ttl],        0
    mov  word [intel_fp_win],        0
    mov  word [intel_fp_mss],        0
    mov  byte [intel_fp_wscale],     0
    mov  byte [intel_fp_sack],       0
    mov  byte [intel_fp_ts],         0
    mov  dword [intel_fp_ts_val],    0
    mov  byte [intel_fp_df],         0
    mov  byte [intel_fp_ipid_class], IPID_UNKNOWN
    mov  dword [intel_fp_opthash],   0
    mov  byte [intel_fp_best_idx],   OS_UNKNOWN
    mov  byte [intel_fp_best_score], 0
    mov  byte [intel_svc_id],        SVC_UNKNOWN
    mov  word [intel_banner_len],    0

    ; Zero score table
    lea  rdi, [intel_fp_scores]
    xor  eax, eax
    mov  ecx, OS_COUNT
    rep  stosb

    pop  rcx
    pop  rdi
    ret

; ------------------------------------------------------------
; intel_rtt_start
; Record RDTSC timestamp before sending probe.
; Call just before SYS_SENDTO in scan loop.
; ------------------------------------------------------------
intel_rtt_start:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [intel_rtt_before], rax
    ret

; ------------------------------------------------------------
; intel_rtt_record
; Compute RTT in microseconds and store in rtt_table.
; Input: ecx = port number (1-based, from scan loop)
; Call after recvfrom() returns a valid packet.
; ------------------------------------------------------------
intel_rtt_record:
    push rax
    push rbx
    push rcx
    push rdx

    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, [intel_rtt_before]    ; delta in TSC cycles
    ; convert to microseconds: (delta * 1000000) / tsc_hz
    mov  rcx, 1000000
    mul  rcx                        ; rdx:rax = delta * 1000000
    mov  rcx, [tsc_hz]
    test rcx, rcx
    jz   .rtt_skip
    div  rcx                        ; rax = microseconds
    ; clamp to 32 bits (anything > 4B us is meaningless)
    cmp  rax, 0xFFFFFFFF
    jbe  .rtt_store
    mov  eax, 0xFFFFFFFF
.rtt_store:
    ; store at rtt_table[(port-1) * 4]
    pop  rcx                        ; restore port
    push rcx
    movzx ebx, cx
    dec  ebx                        ; 0-based
    mov  [intel_rtt_table + rbx*4], eax
.rtt_skip:
    pop  rcx
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ------------------------------------------------------------
; intel_analyze
; Full passive analysis of the SYN-ACK currently in recv_buf.
; Call immediately after validating a SYN-ACK response.
; Input:  rdx = pointer to TCP header inside recv_buf
;         recv_buf = full IP packet
; Populates: intel_fp_* fields, intel_fp_scores[]
; ------------------------------------------------------------
intel_analyze:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13

    mov  r12, rdx                   ; r12 = TCP header pointer

    ; --- [1] TTL: read, classify, compute hop distance ---
    movzx eax, byte [recv_buf+8]
    mov  [intel_fp_ttl], al
    ; infer original TTL
    cmp  al, 64
    jbe  .ttl_64
    cmp  al, 128
    jbe  .ttl_128
    mov  bl, 255                    ; device
    mov  byte [intel_fp_ipid_class], IPID_ZERO  ; devices often have 0 IP ID
    jmp  .ttl_done
.ttl_128:
    mov  bl, 128                    ; Windows
    jmp  .ttl_done
.ttl_64:
    mov  bl, 64                     ; Linux/Unix
.ttl_done:
    sub  bl, al                     ; hops = original - received

    ; --- [2] Window size ---
    movzx eax, word [r12+14]
    xchg al, ah
    mov  [intel_fp_win], ax

    ; --- [3] DF bit (IP flags byte 6-7 bit 14) ---
    movzx eax, word [recv_buf+6]
    xchg al, ah
    test ax, 0x4000
    setz al
    xor  al, 1                      ; al=1 if DF set
    mov  [intel_fp_df], al

    ; --- [4] IP ID field ---
    movzx eax, word [recv_buf+4]
    xchg al, ah
    ; Record in IP ID ring
    movzx ebx, byte [intel_ipid_idx]
    mov  [intel_ipid_ring + rbx*2], ax
    inc  bl
    cmp  bl, IPID_RING_SIZE
    jb   .ipid_stored
    xor  bl, bl
.ipid_stored:
    mov  [intel_ipid_idx], bl
    ; Classify if we have enough samples
    cmp  bl, IPID_RING_SIZE - 1
    jb   .skip_ipid_classify
    call intel_classify_ipid
.skip_ipid_classify:

    ; --- [5] TCP Options parsing ---
    ; Calculate options length from data offset field
    movzx ecx, byte [r12+12]
    shr  ecx, 4                     ; upper nibble = data offset in 4-byte units
    shl  ecx, 2                     ; * 4 = header bytes
    sub  ecx, 20                    ; minus fixed header = options bytes
    jle  .opts_done                 ; no options

    lea  rsi, [r12+20]              ; rsi -> start of TCP options
    xor  r9d, r9d                   ; option order hash

.opt_loop:
    test ecx, ecx
    jle  .opts_done
    movzx eax, byte [rsi]           ; option kind
    cmp  al, 0                      ; EOL
    je   .opts_done
    cmp  al, 1                      ; NOP: 1 byte
    je   .opt_nop

    movzx r8d, byte [rsi+1]         ; option length
    test r8d, r8d
    jz   .opts_done                 ; malformed: length=0, stop

    ; Update option order hash (for option-order fingerprint)
    imul r9d, r9d, 31
    add  r9d, eax

    cmp  al, 2                      ; MSS
    je   .opt_mss
    cmp  al, 3                      ; Window Scale
    je   .opt_wscale
    cmp  al, 4                      ; SACK Permitted
    je   .opt_sack
    cmp  al, 8                      ; Timestamps
    je   .opt_ts
    ; Unknown option: skip by length
    add  rsi, r8
    sub  ecx, r8d
    jmp  .opt_loop

.opt_nop:
    inc  rsi
    dec  ecx
    jmp  .opt_loop

.opt_mss:
    movzx eax, word [rsi+2]
    xchg al, ah
    mov  [intel_fp_mss], ax
    add  rsi, 4
    sub  ecx, 4
    jmp  .opt_loop

.opt_wscale:
    movzx eax, byte [rsi+2]
    mov  [intel_fp_wscale], al
    add  rsi, 3
    sub  ecx, 3
    jmp  .opt_loop

.opt_sack:
    mov  byte [intel_fp_sack], 1
    add  rsi, 2
    sub  ecx, 2
    jmp  .opt_loop

.opt_ts:
    mov  byte [intel_fp_ts], 1
    mov  eax, [rsi+2]
    bswap eax
    mov  [intel_fp_ts_val], eax     ; TSval (remote timestamp)
    add  rsi, 10
    sub  ecx, 10
    jmp  .opt_loop

.opts_done:
    mov  [intel_fp_opthash], r9d

    ; --- [6] LB ring: record TTL, window, TS, opthash ---
    movzx ebx, byte [intel_lb_idx]
    movzx eax, byte [intel_fp_ttl]
    mov  [intel_lb_ttl + rbx], al
    mov  ax, [intel_fp_win]
    mov  [intel_lb_win + rbx*2], ax
    mov  eax, [intel_fp_ts_val]
    mov  [intel_lb_ts + rbx*4], eax
    mov  eax, [intel_fp_opthash]
    mov  [intel_lb_opthash + rbx*4], eax
    inc  bl
    cmp  bl, LB_RING_SIZE
    jb   .lb_stored
    xor  bl, bl
.lb_stored:
    mov  [intel_lb_idx], bl

    ; --- [7] Run the scoring engine ---
    call intel_score

    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ------------------------------------------------------------
; intel_classify_ipid
; Looks at the last IPID_RING_SIZE samples in intel_ipid_ring.
; Sets intel_fp_ipid_class to IPID_xxx constant.
; ------------------------------------------------------------
intel_classify_ipid:
    push rax
    push rbx
    push rcx
    push rsi

    lea  rsi, [intel_ipid_ring]
    xor  ecx, ecx                   ; incremental count
    xor  r8d, r8d                   ; zero count
    xor  r9d, r9d                   ; random count
    xor  r10d, r10d                 ; constant count
    mov  r11d, IPID_RING_SIZE - 1   ; number of diffs to compute

.diff_loop:
    test r11d, r11d
    jz   .classify
    movzx eax, word [rsi]
    movzx ebx, word [rsi+2]
    sub  bx, ax                     ; diff = next - current (wraps mod 65536)
    cmp  bx, 0
    je   .is_zero_diff
    cmp  bx, 1
    je   .is_one
    cmp  bx, 200
    ja   .is_random
    jmp  .diff_next
.is_zero_diff:
    inc  r8d                        ; same ID = zero or constant
    jmp  .diff_next
.is_one:
    inc  ecx                        ; incremental
    jmp  .diff_next
.is_random:
    inc  r9d                        ; random (large jump)
.diff_next:
    add  rsi, 2
    dec  r11d
    jmp  .diff_loop

.classify:
    ; Check all diffs == 0 (ZERO ID, DF set Linux)
    cmp  r8d, IPID_RING_SIZE - 1
    je   .set_zero
    ; Check incremental
    cmp  ecx, IPID_RING_SIZE - 2    ; at least N-2 must be +1
    jge  .set_incremental
    ; Check random
    cmp  r9d, 2
    jge  .set_random
    ; Default: constant or mixed
    mov  byte [intel_fp_ipid_class], IPID_CONSTANT
    jmp  .done
.set_zero:
    mov  byte [intel_fp_ipid_class], IPID_ZERO
    jmp  .done
.set_incremental:
    mov  byte [intel_fp_ipid_class], IPID_INCREMENTAL
    jmp  .done
.set_random:
    mov  byte [intel_fp_ipid_class], IPID_RANDOM

.done:
    pop  rsi
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ------------------------------------------------------------
; intel_score
; Computes a score for each OS candidate using collected fields.
; Updates intel_fp_scores[], intel_fp_best_idx, intel_fp_best_score.
; ------------------------------------------------------------
intel_score:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push r8
    push r9
    push r10

    ; Zero scores first
    lea  rdi, [intel_fp_scores]
    xor  eax, eax
    mov  ecx, OS_COUNT
    rep  stosb

    ; Collect our fingerprint fields into registers for speed
    movzx r8d, byte [intel_fp_ttl]      ; r8d = received TTL
    movzx r9d, word [intel_fp_win]      ; r9d = window size
    movzx r10d, word [intel_fp_mss]     ; r10d = MSS

    ; Derive TTL class
    xor  ecx, ecx
    cmp  r8b, 70
    jbe  .ttl_class_done
    mov  ecx, 1
    cmp  r8b, 130
    jbe  .ttl_class_done
    mov  ecx, 2
.ttl_class_done:
    ; ecx = ttl_class: 0=Linux, 1=Windows, 2=Device

    ; Iterate OS DB entries
    lea  rsi, [intel_os_db]
    xor  ebx, ebx                       ; OS index counter

.score_loop:
    cmp  ebx, intel_os_db_count
    jae  .score_done

    xor  edx, edx                       ; this entry's score

    ; Window range check
    movzx eax, word [rsi]               ; win_lo
    cmp  r9d, eax
    jb   .win_miss
    movzx eax, word [rsi+2]             ; win_hi
    cmp  r9d, eax
    ja   .win_miss
    add  edx, SCORE_WINDOW
.win_miss:

    ; TTL class check
    movzx eax, byte [rsi+4]             ; ttl_class
    cmp  ecx, eax
    jne  .ttl_miss
    add  edx, SCORE_TTL
.ttl_miss:

    ; MSS range check (only if MSS was captured)
    test r10d, r10d
    jz   .mss_skip
    movzx eax, word [rsi+5]             ; mss_lo
    cmp  r10d, eax
    jb   .mss_miss
    movzx eax, word [rsi+7]             ; mss_hi
    cmp  r10d, eax
    ja   .mss_miss
    add  edx, SCORE_MSS
.mss_miss:
.mss_skip:

    ; WScale check
    movzx eax, byte [rsi+9]             ; expected wscale
    movzx r11d, byte [intel_fp_wscale]
    cmp  r11d, eax
    jne  .ws_miss
    add  edx, SCORE_WSCALE
.ws_miss:

    ; SACK check
    movzx eax, byte [rsi+10]            ; expected sack
    movzx r11d, byte [intel_fp_sack]
    cmp  r11d, eax
    jne  .sack_miss
    add  edx, SCORE_SACK
.sack_miss:

    ; TS check
    movzx eax, byte [rsi+11]            ; expected ts
    movzx r11d, byte [intel_fp_ts]
    cmp  r11d, eax
    jne  .ts_miss
    add  edx, SCORE_TS
.ts_miss:

    ; DF check
    movzx eax, byte [rsi+12]            ; expected df
    movzx r11d, byte [intel_fp_df]
    cmp  r11d, eax
    jne  .df_miss
    add  edx, SCORE_DF
.df_miss:

    ; Store score for this OS
    movzx eax, byte [rsi+13]            ; os_id
    mov  [intel_fp_scores + rax], dl    ; store score (low byte)

    add  rsi, 16                        ; next DB entry (16 bytes each)
    inc  ebx
    jmp  .score_loop

.score_done:
    ; Find highest score
    lea  rsi, [intel_fp_scores]
    xor  eax, eax                       ; best score
    xor  ecx, ecx                       ; best index
    mov  r8d, OS_COUNT

.find_best:
    movzx ebx, byte [rsi]
    cmp  ebx, eax
    jle  .find_next
    mov  eax, ebx
    mov  ecx, OS_COUNT
    sub  ecx, r8d                       ; current index = OS_COUNT - remaining
.find_next:
    inc  rsi
    dec  r8d
    jnz  .find_best

    ; If best score < CONF_LOW, force UNKNOWN
    cmp  al, CONF_LOW
    jae  .store_best
    mov  ecx, OS_UNKNOWN
    xor  eax, eax
.store_best:
    mov  [intel_fp_best_idx], cl
    mov  [intel_fp_best_score], al

    pop  r10
    pop  r9
    pop  r8
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ------------------------------------------------------------
; intel_lb_check
; Scan the LB rings for variation indicating a load balancer.
; Sets ZF if no load balancer detected, clears ZF if detected.
; Call after filling at least 3 LB ring slots (3 probes same port).
; ------------------------------------------------------------
intel_lb_check:
    push rax
    push rbx
    push rcx
    push rsi

    ; Check TTL variation
    lea  rsi, [intel_lb_ttl]
    movzx eax, byte [rsi]
    mov  ecx, LB_RING_SIZE - 1
.ttl_check:
    inc  rsi
    movzx ebx, byte [rsi]
    cmp  bl, al
    jne  .lb_detected
    loop .ttl_check

    ; Check window variation
    lea  rsi, [intel_lb_win]
    movzx eax, word [rsi]
    mov  ecx, LB_RING_SIZE - 1
.win_check:
    add  rsi, 2
    movzx ebx, word [rsi]
    cmp  bx, ax
    jne  .lb_detected
    loop .win_check

    ; Check option hash variation
    lea  rsi, [intel_lb_opthash]
    mov  eax, [rsi]
    mov  ecx, LB_RING_SIZE - 1
.hash_check:
    add  rsi, 4
    mov  ebx, [rsi]
    cmp  ebx, eax
    jne  .lb_detected
    loop .hash_check

    ; No variation: not a load balancer
    xor  eax, eax
    test eax, eax                   ; set ZF
    jmp  .lb_done

.lb_detected:
    mov  eax, 1
    test eax, eax                   ; clear ZF

.lb_done:
    pop  rsi
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ------------------------------------------------------------
; intel_banner_match
; Match first N bytes of recv_buf against banner signature table.
; Input:  eax = number of bytes received in recv_buf
; Populates: intel_svc_id, intel_svc_name, intel_banner, intel_banner_len
; ------------------------------------------------------------
intel_banner_match:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9

    ; Copy up to 64 bytes into intel_banner
    cmp  eax, 64
    jbe  .copy_banner
    mov  eax, 64
.copy_banner:
    mov  [intel_banner_len], ax
    lea  rdi, [intel_banner]
    lea  rsi, [recv_buf]
    mov  rcx, rax
    rep  movsb

    ; Iterate signature table
    lea  r8, [intel_banner_db]

.sig_loop:
    movzx ecx, byte [r8+1]          ; pattern length
    test ecx, ecx
    jz   .sig_no_match              ; terminator

    movzx eax, byte [r8]            ; offset into banner
    lea  rdi, [intel_banner + rax]  ; banner pointer + offset
    lea  rsi, [r8+2]                ; pattern pointer

    ; Bounds check: offset + length must not exceed banner_len
    movzx r9d, word [intel_banner_len]
    add  r9d, eax
    cmp  r9d, ecx
    jl   .sig_next                  ; not enough banner bytes

    ; Compare ecx bytes
    push rdi
    push rsi
    push rcx
    repe cmpsb
    pop  rcx
    pop  rsi
    pop  rdi
    jne  .sig_next

    ; Match found
    movzx eax, byte [r8+18]         ; svc_id
    mov  [intel_svc_id], al
    ; Copy service name (13 bytes max, null-terminated)
    lea  rsi, [r8+19]
    lea  rdi, [intel_svc_name]
    mov  ecx, 13
    rep  movsb
    jmp  .sig_done

.sig_next:
    add  r8, SIG_ENTRY_SIZE
    jmp  .sig_loop

.sig_no_match:
    mov  byte [intel_svc_id], SVC_UNKNOWN
    mov  byte [intel_svc_name], 0

.sig_done:
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ------------------------------------------------------------
; intel_print_record
; Print one full intel line for an open port.
; Input: ecx = port number (1-based)
; Format:
;   PORT  STATE   TTL HOP WIN   MSS  OS             RTT   SVC
;   22    OPEN    62  2   65535 1460 Linux-5.x/6.x  1.2ms SSH
; ------------------------------------------------------------
intel_print_record:
    push rax
    push rbx
    push rcx
    push rdx

    ; Port number
    mov  ax, cx
    call append_u16

    ; TTL
    lea  rsi, [intel_lbl_ttl]
    call .print_cstr
    movzx ax, byte [intel_fp_ttl]
    call append_u16

    ; Hop distance
    lea  rsi, [intel_lbl_hops]
    call .print_cstr
    movzx eax, byte [intel_fp_ttl]
    ; derive original TTL
    mov  ebx, 64
    cmp  al, 64
    jbe  .hop_64
    mov  ebx, 128
    cmp  al, 128
    jbe  .hop_128
    mov  ebx, 255
.hop_64:
.hop_128:
    sub  bl, al
    movzx ax, bl
    call append_u16

    ; Window
    lea  rsi, [intel_lbl_win]
    call .print_cstr
    mov  ax, [intel_fp_win]
    call append_u16

    ; MSS (if captured)
    mov  ax, [intel_fp_mss]
    test ax, ax
    jz   .no_mss
    lea  rsi, [intel_lbl_mss]
    call .print_cstr
    call append_u16
.no_mss:

    ; Flags: SACK, TS, DF
    cmp  byte [intel_fp_sack], 1
    jne  .no_sack
    lea  rsi, [intel_lbl_sack]
    call .print_cstr
.no_sack:
    cmp  byte [intel_fp_ts], 1
    jne  .no_ts
    lea  rsi, [intel_lbl_ts]
    call .print_cstr
.no_ts:
    cmp  byte [intel_fp_df], 1
    jne  .no_df
    lea  rsi, [intel_lbl_df]
    call .print_cstr
.no_df:

    ; OS fingerprint
    lea  rsi, [intel_lbl_os]
    call .print_cstr
    movzx eax, byte [intel_fp_best_idx]
    cmp  eax, OS_COUNT
    jb   .os_idx_ok
    mov  eax, OS_UNKNOWN
.os_idx_ok:
    mov  rsi, [intel_os_name_ptrs + rax*8]
    call .print_cstr
    ; Confidence label
    movzx eax, byte [intel_fp_best_score]
    cmp  al, CONF_HIGH
    jae  .conf_high
    cmp  al, CONF_MED
    jae  .conf_med
    cmp  al, CONF_LOW
    jae  .conf_low
    lea  rsi, [intel_conf_unk]
    jmp  .conf_done
.conf_high:
    lea  rsi, [intel_conf_high]
    jmp  .conf_done
.conf_med:
    lea  rsi, [intel_conf_med]
    jmp  .conf_done
.conf_low:
    lea  rsi, [intel_conf_low]
.conf_done:
    call .print_cstr

    ; RTT
    movzx eax, cx
    dec  eax
    mov  edx, [intel_rtt_table + eax*4]
    test edx, edx
    jz   .no_rtt
    lea  rsi, [intel_lbl_rtt]
    call .print_cstr
    cmp  edx, 999
    ja   .rtt_ms
    ; microseconds
    mov  ax, dx
    call append_u16
    lea  rsi, [intel_lbl_us]
    call .print_cstr
    jmp  .no_rtt
.rtt_ms:
    ; convert to ms
    xor  edx, edx
    mov  eax, edx
    movzx eax, cx
    dec  eax
    mov  edx, [intel_rtt_table + eax*4]
    mov  eax, edx
    mov  ecx, 1000
    xor  edx, edx
    div  ecx
    call append_u16
    lea  rsi, [intel_lbl_ms]
    call .print_cstr
.no_rtt:

    ; Service name from banner match
    cmp  byte [intel_svc_id], SVC_UNKNOWN
    je   .no_svc
    lea  rsi, [intel_lbl_svc]
    call .print_cstr
    lea  rsi, [intel_svc_name]
    call .print_cstr
.no_svc:

    ; IPID annotations
    cmp  byte [intel_fp_ipid_class], IPID_INCREMENTAL
    jne  .no_zombie
    lea  rsi, [intel_lbl_zombie]
    call .print_cstr
.no_zombie:

    ; LB check annotation
    call intel_lb_check
    jz   .no_lb
    lea  rsi, [intel_lbl_lb]
    call .print_cstr
.no_lb:

    ; Newline
    lea  rsi, [intel_lbl_newline]
    call .print_cstr

    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

    ; Helper: print null-terminated string from rsi via buf_write
.print_cstr:
    push rsi
    push rdx
    push rcx
    xor  edx, edx
.strlen:
    cmp  byte [rsi+rdx], 0
    je   .strlen_done
    inc  edx
    jmp  .strlen
.strlen_done:
    call buf_write
    pop  rcx
    pop  rdx
    pop  rsi
    ret

; ------------------------------------------------------------
; intel_print_rtt_map
; After scan: print any ports whose RTT is > 2x the mean RTT.
; Helps identify: filtered ports, proxies, overloaded services.
; ------------------------------------------------------------
intel_print_rtt_map:
    push rax
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10

    ; Compute mean RTT across all ports that have a result
    xor  r8d, r8d                   ; sum (low 32 bits, truncate for mean)
    xor  r9d, r9d                   ; count
    movzx ecx, word [start_port]
    movzx r10d, word [end_port]

.mean_loop:
    cmp  ecx, r10d
    ja   .mean_done
    movzx eax, cx
    dec  eax
    mov  edx, [intel_rtt_table + eax*4]
    test edx, edx
    jz   .mean_next
    add  r8d, edx
    inc  r9d
.mean_next:
    inc  ecx
    jmp  .mean_loop

.mean_done:
    test r9d, r9d
    jz   .rtt_map_done

    ; mean = sum / count
    mov  eax, r8d
    xor  edx, edx
    div  r9d                        ; eax = mean RTT in us

    ; threshold = mean * 2
    mov  r8d, eax
    shl  r8d, 1                     ; r8d = threshold

    ; Print header only if any outliers exist
    xor  r11d, r11d                 ; header_printed flag

    movzx ecx, word [start_port]
.outlier_loop:
    cmp  ecx, r10d
    ja   .rtt_map_done
    movzx eax, cx
    dec  eax
    mov  edx, [intel_rtt_table + eax*4]
    test edx, edx
    jz   .outlier_next
    cmp  edx, r8d
    jbe  .outlier_next
    ; Outlier found
    test r11d, r11d
    jnz  .outlier_print
    ; Print header first time
    lea  rsi, [intel_rtt_hdr]
    push rcx
    push rdx
    xor  edx, edx
.hdr_len:
    cmp  byte [rsi+rdx], 0
    je   .hdr_done
    inc  edx
    jmp  .hdr_len
.hdr_done:
    call buf_write
    pop  rdx
    pop  rcx
    mov  r11d, 1
.outlier_print:
    mov  ax, cx
    call append_u16
    lea  rsi, [intel_lbl_rtt]
    push rcx
    push rdx
    xor  edx, edx
.rtt_lbl_len:
    cmp  byte [rsi+rdx], 0
    je   .rtt_lbl_done
    inc  edx
    jmp  .rtt_lbl_len
.rtt_lbl_done:
    call buf_write
    mov  eax, edx
    pop  rdx
    pop  rcx
    mov  ax, dx
    call append_u16
    lea  rsi, [intel_lbl_slow]
    push rcx
    push rdx
    xor  edx, edx
.slow_len:
    cmp  byte [rsi+rdx], 0
    je   .slow_done
    inc  edx
    jmp  .slow_len
.slow_done:
    call buf_write
    pop  rdx
    pop  rcx
    lea  rsi, [intel_lbl_newline]
    mov  edx, 1
    call buf_write

.outlier_next:
    inc  ecx
    jmp  .outlier_loop

.rtt_map_done:
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    ret

%endif ; INTELLIGENCE_INC
