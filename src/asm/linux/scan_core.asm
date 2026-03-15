; ============================================================
; NetroX-ASM Hybrid | Linux hot-path scan core (WIP extraction)
; ============================================================
; NOTE: This file is being split from src/linux/main.asm.
; The cold-path is now in C++; hot-path remains in ASM.

%ifndef SCAN_CORE_LINUX_ASM
%define SCAN_CORE_LINUX_ASM 1

default rel

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
global asm_get_tsc_hz
global asm_scan_cleanup
extern asm_get_local_ip
extern setup_send_engine
extern setup_sigint_handler

; ------------------------------------------------------------
; asm_scan_init
; ------------------------------------------------------------
asm_scan_init:
    ; TODO: wire full init from legacy main.asm
    ; For now, just store cfg_ptr and return 0.
    mov [cfg_ptr], rdi
    xor eax, eax
    ret

; ------------------------------------------------------------
; asm_scan_run
; ------------------------------------------------------------
asm_scan_run:
    ; TODO: full scan loop extraction
    ; TODO: implement full init; scan loop already extracted
    xor eax, eax
    ret

; ------------------------------------------------------------
; asm_get_local_ip
; ------------------------------------------------------------
asm_get_local_ip:
    ; TODO: implemented in network.asm
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
