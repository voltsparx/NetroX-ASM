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
            db "       [--stabilize] [--about] [--wizard]", 13, 10
            db "Scan modes: syn ack fin null xmas window maimon", 13, 10
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

    mov rdi, rdx

.arg_loop:
    call next_token
    test rax, rax
    jz .ports_ready
    mov rsi, rax
    cmp byte [rsi], '-'
    jne .arg_next

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
    jne .check_bench
    cmp dword [rsi+2], 'scan'
    jne .check_bench
    cmp byte [rsi+6], 0
    jne .check_bench
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

    call init_rate
    call intel_init

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

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]

; -------------------------------------------------------------------
; Scan loop
; -------------------------------------------------------------------
.scan_loop:
    cmp ecx, r15d
    ja .scan_done

    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    call build_packet
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
    cmp byte [stab_enabled], 0
    je .filtered_no_stab
    inc dword [stab_timeout]
.filtered_no_stab:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result

.next_port:
    call stabilize_step
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
