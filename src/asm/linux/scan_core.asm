; ============================================================
; NetroX-ASC Hybrid | Linux hot-path scan core (WIP extraction)
; ============================================================
; NOTE: This file is being split from src/linux/main.asm.
; The cold-path is now in C++; hot-path remains in ASM.

%ifndef SCAN_CORE_LINUX_ASM
%define SCAN_CORE_LINUX_ASM 1

default rel
; ScanConfig offsets (must match include/netrox_abi.h)
%define CFG_TARGET_IP        0
%define CFG_TARGET_MASK      4
%define CFG_CIDR_MODE        8
%define CFG_IPV6_MODE        9
%define CFG_START_PORT       10
%define CFG_END_PORT         12
%define CFG_PORT_LIST        16
%define CFG_PORT_LIST_COUNT  24
%define CFG_TOP_PORTS_MODE   26
%define CFG_TOP_PORTS_N      28
%define CFG_SEQUENTIAL_MODE  30
%define CFG_FAST_MODE        31
%define CFG_SCAN_MODE        32
%define CFG_ENGINE_MODE      33
%define CFG_RATE_PPS         36
%define CFG_SCAN_DELAY_US    40
%define CFG_MAX_SCAN_DELAY_US 44
%define CFG_MIN_RATE         48
%define CFG_MIN_PARALLEL     52
%define CFG_MAX_PARALLEL     54
%define CFG_HOST_TIMEOUT     56
%define CFG_RETRY_COUNT      64
%define CFG_TIMING_TEMPLATE  65
%define CFG_STAB_ENABLED     66
%define CFG_JSON_MODE        67
%define CFG_CSV_MODE         68
%define CFG_QUIET_MODE       69
%define CFG_REASON_MODE      70
%define CFG_PACKET_TRACE     71
%define CFG_VERBOSITY        72
%define CFG_DEBUG_LEVEL      73
%define CFG_BENCH_MODE       74
%define CFG_OUTPUT_FILE      80
%define CFG_OX_PATH          88
%define CFG_OG_PATH          96
%define CFG_OS_DETECT        104
%define CFG_VERSION_ENABLED  105
%define CFG_VERSION_INTENSITY 106
%define CFG_BANNERS_MODE     107
%define CFG_IFACE            108
%define CFG_LOCAL_IP         124
%define CFG_FRAG_MODE        128
%define CFG_FRAG_MTU         130
%define CFG_SPOOF_SRC_IP     132
%define CFG_CUSTOM_TTL       136
%define CFG_BADSUM_MODE      137
%define CFG_DECOY_LIST       140
%define CFG_DECOY_COUNT      172
%define CFG_DECOY_ME_POS     173
%define CFG_CUSTOM_DATA      174
%define CFG_CUSTOM_DATA_LEN  238
%define CFG_RANDOM_DATA_LEN  239
%define CFG_SRC_PORT         240
%define CFG_ZOMBIE_IP        244
%define CFG_ZOMBIE_PORT      248
%define CFG_FTP_PROXY_IP     252
%define CFG_FTP_PROXY_PORT   256
%define CFG_ON_PORT_RESULT   264
%define CFG_ON_HOST_UP       272
%define CFG_ON_SCAN_DONE     280

SECTION .bss
; Hot-path only state (minimal subset for now)
raw_fd          resd 1
recv_fd         resd 1
epoll_fd        resd 1
cfg_ptr         resq 1
tsc_hz          resq 1
rate_cycles     resq 1
rate_enabled    resb 1
last_send_tsc   resq 1
rate_min_cycles resq 1
rate_max_cycles resq 1
scan_seed       resq 1
xorshift_state  resq 1
local_ip        resd 1
rate_value      resd 1
ts_start        resq 1
ts_end          resq 1
tsc_start       resq 1
blackrock_key_0 resq 1
blackrock_key_1 resq 1
blackrock_key_2 resq 1
blackrock_key_3 resq 1
blackrock_key_4 resq 1
blackrock_key_5 resq 1
scan_done_flag  resb 1

; CIDR index state (temporary while refactoring)
ip_ranges         resb 128 * 8
ip_range_count    resd 1
total_ip_count    resq 1
current_scan_ip   resd 1

; Port list state (temporary)
start_port        resw 1
end_port          resw 1
port_list_mode    resb 1
port_list_count   resw 1
port_list_buf     resw 256
top_ports_mode    resb 1
top_ports_n       resw 1
top_ports_ptr     resq 1

; Result bitmap
result_map        resb 8192
open_count        resd 1

SECTION .text

global asm_scan_init
global asm_scan_run
global asm_get_local_ip
global asm_get_tsc_hz
global asm_scan_cleanup
extern setup_send_engine
extern setup_sigint_handler
extern asm_get_local_ip_internal

; ------------------------------------------------------------
; asm_scan_init
; ------------------------------------------------------------
asm_scan_init:
    mov [cfg_ptr], rdi
    mov eax, [rdi + CFG_TARGET_IP]
    mov [target_ip], eax
    mov al, [rdi + CFG_SCAN_MODE]
    mov [scan_mode], al
    mov al, [rdi + CFG_CIDR_MODE]
    mov [cidr_mode], al
    mov ax, [rdi + CFG_START_PORT]
    mov [start_port], ax
    mov ax, [rdi + CFG_END_PORT]
    mov [end_port], ax
    mov eax, [rdi + CFG_RATE_PPS]
    mov [rate_value], eax
    mov al, [rdi + CFG_OS_DETECT]
    mov [os_enabled], al
    mov al, [rdi + CFG_RETRY_COUNT]
    mov [retry_max], al
    mov al, [rdi + CFG_STAB_ENABLED]
    mov [stab_enabled], al
    ; port list copy (if provided)
    movzx ecx, word [rdi + CFG_PORT_LIST_COUNT]
    test ecx, ecx
    jz .no_port_list
    mov rbx, [rdi + CFG_PORT_LIST]
    test rbx, rbx
    jz .no_port_list
    mov [port_list_count], cx
    mov byte [port_list_mode], 1
    lea rsi, [port_list_buf]
    xor edx, edx
.pl_copy:
    cmp dx, cx
    jae .pl_done
    mov ax, [rbx + rdx*2]
    mov [rsi + rdx*2], ax
    inc dx
    jmp .pl_copy
.pl_done:
    jmp .port_list_done
.no_port_list:
    mov byte [port_list_mode], 0
.port_list_done:
    mov al, [rdi + CFG_TOP_PORTS_MODE]
    mov [top_ports_mode], al
    mov ax, [rdi + CFG_TOP_PORTS_N]
    mov [top_ports_n], ax
    mov eax, [rdi + CFG_LOCAL_IP]
    mov [local_ip], eax
    test eax, eax
    jnz .have_local_ip
    call asm_get_local_ip
.have_local_ip:
    mov eax, [local_ip]
    mov [source_ip], eax

    call blackrock_init
    call cookie_init
    call init_rate
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [xorshift_state], rax
    xor eax, eax
    ret
; ------------------------------------------------------------
; asm_scan_run
; ------------------------------------------------------------
asm_scan_run:
    ; Open raw socket
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_RAW
    mov rdx, IPPROTO_TCP
    syscall
    test rax, rax
    js .scan_fail
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
    js .scan_fail

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
    js .scan_fail
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
    js .scan_fail

    call setup_sigint_handler
    call init_packet_template

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    call setup_send_engine
    test eax, eax
    jnz .scan_fail

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov r14d, r15d
    sub r14d, ecx
    inc r14d
    mov r15d, r14d
    mov r14d, ecx
    xor ebx, ebx
    xor r13, r13

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
    mov r15, [total_ip_count]
    test r15, r15
    jz .scan_ready_done
    ; total scans = total_ip_count * port_count
    mov rax, r15
    movzx rcx, word [end_port]
    movzx rdx, word [start_port]
    sub rcx, rdx
    inc rcx
    mul rcx
    mov r15, rax
    xor r14d, r14d
.scan_ready_done:
    call scan_loop_entry
    xor eax, eax
    ret
.scan_fail:
    mov eax, 1
    ret
; ------------------------------------------------------------
; asm_get_local_ip
; ------------------------------------------------------------
asm_get_local_ip:
    push rdi
    call asm_get_local_ip_internal
    pop rdi
    mov eax, [local_ip]
    mov [rdi + CFG_LOCAL_IP], eax
    xor eax, eax
    ret
; ------------------------------------------------------------
; asm_get_tsc_hz
; ------------------------------------------------------------
asm_get_tsc_hz:
    mov rax, [tsc_hz]
    ret

; ------------------------------------------------------------
; asm_scan_cleanup
; ------------------------------------------------------------
asm_scan_cleanup:
    mov rax, [send_fd]
    test rax, rax
    jz .skip_send
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall
.skip_send:
    mov rax, [raw_fd]
    test rax, rax
    jz .skip_raw
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall
.skip_raw:
    mov rax, [epoll_fd]
    test rax, rax
    jz .done
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall
.done:
    ret

; -------------------------------------------------------------------
; intelligence_gate
; -------------------------------------------------------------------
intelligence_gate:
    call rate_gate
    ret

; -------------------------------------------------------------------
; rate_gate
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
; record_open  ecx=port
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
    div  rbx
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
    ret

; -------------------------------------------------------------------
; init_rate
; -------------------------------------------------------------------
init_rate:
    mov eax, [rate_value]
    test eax, eax
    jnz .do
    call calibrate_tsc
    jmp .done
.do:
    call calibrate_tsc
    mov ecx, [rate_value]
    mov rax, [tsc_hz]
    xor rdx, rdx
    div rcx
    mov [rate_cycles], rax
    mov byte [rate_enabled], 1
.done:
    ret

; -------------------------------------------------------------------
; calibrate_tsc
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
    cmp rax, 50000000
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
; stabilize_step / slow_down / speed_up
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
; Main scan loop (extracted from legacy main.asm)
; NOTE: output callbacks still need conversion to C++.
; -------------------------------------------------------------------
scan_loop_entry:
.scan_loop:
    cmp rbx, r15
    jae .scan_done
    mov [resume_index], rbx

    cmp byte [scan_mode], SCAN_SEQ
    je .seq_index
    mov rdi, rbx
    mov rsi, r15
    call blackrock_permute
    jmp .index_ready
.seq_index:
    mov eax, ebx
.index_ready:
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

    mov rax, SYS_SENDTO
    mov rdi, [send_fd]
    lea rsi, [packet_buf]
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

    lea rsi, [recv_buf]
    mov al, [rsi+9]
    cmp al, 6
    jne .recv_mismatch
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .recv_mismatch
    mov al, [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]
    mov ax, [rdx]
    cmp ax, [dst_port_be]
    jne .recv_mismatch
    mov ax, [rdx+2]
    cmp ax, [src_port_be]
    jne .recv_mismatch

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

.recv_mismatch:
    dec r11d
    jnz .epoll_loop
    jmp .report_filtered

.epoll_noevent:
    dec r11d
    jnz .epoll_loop
    jmp .report_filtered

.report_open:
    mov byte [retry_cur], 0
    call record_open
    ; callback: PortResult (open)
    sub rsp, 128
    mov word [rsp], cx           ; port
    mov byte [rsp+2], 1          ; state=open
    mov byte [rsp+3], 0          ; proto=tcp
    mov eax, [last_rtt_ns]
    mov [rsp+4], eax
    mov byte [rsp+8], 0
    mov byte [rsp+40], 0
    mov byte [rsp+104], 0
    mov rax, [cfg_ptr]
    mov rax, [rax + 264]         ; on_port_result
    test rax, rax
    jz .cb_open_done
    mov rdi, rsp
    call rax
.cb_open_done:
    add rsp, 128
    jmp .next_port

.report_closed:
    mov byte [retry_cur], 0
    inc dword [closed_count]
    ; callback: PortResult (closed)
    sub rsp, 128
    mov word [rsp], cx
    mov byte [rsp+2], 0          ; state=closed
    mov byte [rsp+3], 0
    mov eax, [last_rtt_ns]
    mov [rsp+4], eax
    mov byte [rsp+8], 0
    mov byte [rsp+40], 0
    mov byte [rsp+104], 0
    mov rax, [cfg_ptr]
    mov rax, [rax + 264]
    test rax, rax
    jz .cb_closed_done
    mov rdi, rsp
    call rax
.cb_closed_done:
    add rsp, 128
    jmp .next_port

.report_filtered:
    mov al, [retry_cur]
    cmp al, [retry_max]
    jb .retry_again
    mov byte [retry_cur], 0
    inc dword [filtered_count]
    ; callback: PortResult (filtered)
    sub rsp, 128
    mov word [rsp], cx
    mov byte [rsp+2], 2          ; state=filtered
    mov byte [rsp+3], 0
    mov eax, [last_rtt_ns]
    mov [rsp+4], eax
    mov byte [rsp+8], 0
    mov byte [rsp+40], 0
    mov byte [rsp+104], 0
    mov rax, [cfg_ptr]
    mov rax, [rax + 264]
    test rax, rax
    jz .cb_filt_done
    mov rdi, rsp
    call rax
.cb_filt_done:
    add rsp, 128
    jmp .next_port

.retry_again:
    inc byte [retry_cur]
    jmp .retry_send

.next_port:
    call stabilize_step
    inc rbx
    jmp .scan_loop

.scan_done:
    ret

; ------------------------------------------------------------
; Include common ASM components (hot-path)
; ------------------------------------------------------------
%include "../common/constants.inc"
%include "../common/scan.inc"
%include "../common/packet.inc"
%include "../common/checksum.inc"
%include "../common/engine.inc"
%include "../common/intelligence.inc"
%include "../common/engines/dispatch.inc"

%endif







