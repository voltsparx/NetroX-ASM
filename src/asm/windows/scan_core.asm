; ============================================================
; NetroX-ASM Hybrid | Windows hot-path scan core (WIP extraction)
; ============================================================
%ifndef SCAN_CORE_WINDOWS_ASM
%define SCAN_CORE_WINDOWS_ASM 1

default rel

%ifndef SOCKET_ERROR
%define SOCKET_ERROR -1
%endif
%ifndef INVALID_SOCKET
%define INVALID_SOCKET -1
%endif

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
cfg_ptr         resq 1
tsc_hz          resq 1
scan_done_flag  resb 1
scan_seed       resq 1
local_ip        resd 1
xorshift_state  resq 1
blackrock_key_0 resq 1
blackrock_key_1 resq 1
blackrock_key_2 resq 1
blackrock_key_3 resq 1
blackrock_key_4 resq 1
blackrock_key_5 resq 1
rate_cycles     resq 1
rate_enabled    resb 1
last_send_tsc   resq 1
rate_min_cycles resq 1
rate_max_cycles resq 1

SECTION .text
global asm_scan_init
global asm_scan_run
global asm_get_tsc_hz
global asm_scan_cleanup

asm_scan_init:
    mov [cfg_ptr], rdi
    ; cache minimal config into hot-path vars
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
    mov al, [rdi + CFG_RETRY_COUNT]
    mov [retry_max], al
    mov al, [rdi + CFG_STAB_ENABLED]
    mov [stab_enabled], al
    ; local IP: from cfg if provided, else discover
    mov eax, [rdi + CFG_LOCAL_IP]
    mov [local_ip], eax
    test eax, eax
    jnz .have_local_ip
    call asm_get_local_ip
.have_local_ip:
    mov eax, [local_ip]
    mov [source_ip], eax

    ; WSAStartup
    sub rsp, 40
    mov ecx, 0x0202
    lea rdx, [wsa_data]
    call WSAStartup
    add rsp, 40

    call setup_sigint_handler
    call blackrock_init
    call cookie_init
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [xorshift_state], rax
    xor eax, eax
    ret

asm_scan_run:
    ; open raw socket if needed
    mov rax, [sock_fd]
    cmp rax, INVALID_SOCKET
    jne .sock_ready
    sub rsp, 40
    mov ecx, AF_INET
    mov edx, SOCK_RAW
    mov r8d, IPPROTO_TCP
    call socket
    add rsp, 40
    cmp rax, INVALID_SOCKET
    je .scan_fail
    mov [sock_fd], rax

    sub rsp, 40
    mov rcx, [sock_fd]
    mov edx, IPPROTO_IP
    mov r8d, IP_HDRINCL
    lea r9, [hdrincl]
    mov dword [rsp+32], 4
    call setsockopt
    add rsp, 40

    sub rsp, 40
    mov rcx, [sock_fd]
    mov edx, SOL_SOCKET
    mov r8d, SO_RCVTIMEO
    lea r9, [timeout_ms]
    mov dword [rsp+32], 4
    call setsockopt
    add rsp, 40
.sock_ready:
    call init_packet_template

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

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
    mov r15, [total_index_max]
    xor r14d, r14d
.scan_ready_done:
    call scan_loop_entry
    xor eax, eax
    ret
.scan_fail:
    mov eax, 1
    ret

asm_get_tsc_hz:
    mov rax, [tsc_hz]
    ret

asm_scan_cleanup:
    ret

; -------------------------------------------------------------------
; cookie_init / generate / verify (same as Linux)
; -------------------------------------------------------------------
cookie_init:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [scan_seed], rax
    ret

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

cookie_verify:
    push rax
    call cookie_generate
    inc  eax
    cmp  edx, eax
    pop  rax
    ret

; -------------------------------------------------------------------
; xorshift64_next
; -------------------------------------------------------------------
xorshift64_next:
    mov rax, [xorshift_state]
    mov rbx, rax
    shl rbx, 13
    xor rax, rbx
    mov rbx, rax
    shr rbx, 7
    xor rax, rbx
    mov rbx, rax
    shl rbx, 17
    xor rax, rbx
    mov [xorshift_state], rax
    ret

; -------------------------------------------------------------------
; blackrock_init / feistel_f / blackrock_permute
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

feistel_f:
    mov rax, r9
    add rax, r10
    mov rcx, 0x9e3779b97f4a7c15
    mul rcx
    xor rax, rdx
    rol rax, 17
    ret

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
; index_to_ip_port (same as Linux)
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
; Main scan loop (Windows)
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
    xchg al, ah
    mov [dst_port_be], ax
    call build_packet
.retry_send:
    call intel_rtt_start
    call intelligence_gate

    mov edx, 40
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
    cmp eax, SOCKET_ERROR
    je .error

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
    mov al, [rsi+9]
    cmp al, 6
    jne .report_filtered
    mov eax, [rsi+12]
    cmp byte [cidr_mode], 0
    jne .src_ok
    cmp eax, [target_ip]
    jne .report_filtered
.src_ok:
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
    mov r8d, [rdx+8]
    bswap r8d
    mov edi, [rsi+12]
    mov edx, r8d
    call cookie_verify
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
    ; callback PortResult open
    sub rsp, 128
    mov word [rsp], cx
    mov byte [rsp+2], 1
    mov byte [rsp+3], 0
    mov eax, [last_rtt_ns]
    mov [rsp+4], eax
    mov byte [rsp+8], 0
    mov byte [rsp+40], 0
    mov byte [rsp+104], 0
    mov rax, [cfg_ptr]
    mov rax, [rax + 264]
    test rax, rax
    jz .cb_open_done
    mov rdi, rsp
    call rax
.cb_open_done:
    add rsp, 128
    jmp .next_port

.report_closed:
    mov byte [retry_cur], 0
    ; callback PortResult closed
    sub rsp, 128
    mov word [rsp], cx
    mov byte [rsp+2], 0
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
    ; callback PortResult filtered
    sub rsp, 128
    mov word [rsp], cx
    mov byte [rsp+2], 2
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

%include "../common/constants.inc"
%include "../common/scan.inc"
%include "../common/packet.inc"
%include "../common/checksum.inc"
%include "../common/engine.inc"
%include "../common/intelligence.inc"
%include "../common/engines/dispatch.inc"

extern asm_get_local_ip
extern setup_sigint_handler
extern WSAStartup
extern socket
extern setsockopt
extern closesocket
extern sendto
extern recvfrom

%endif
