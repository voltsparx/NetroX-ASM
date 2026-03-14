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
extern WriteFile
extern ExitProcess

%include "../common/parse.inc"
%include "../common/checksum.inc"
%include "../common/packet.inc"
%include "../common/engine.inc"

%define AF_INET 2
%define SOCK_RAW 3
%define SOCK_DGRAM 2
%define IPPROTO_IP 0
%define IPPROTO_TCP 6
%define IPPROTO_UDP 17
%define IP_HDRINCL 2
%define SOL_SOCKET 0xFFFF
%define SO_RCVTIMEO 0x1006
%define INVALID_SOCKET -1
%define SOCKET_ERROR -1
%define STD_OUTPUT_HANDLE -11
%define OUTPUT_BUF_SIZE 131072
%define OUTPUT_FLUSH_THRESHOLD 98304

SECTION .data
usage_msg db "Usage: netx-asm.exe <target_ip> [-p port|start-end|-] [--rate N] [--scan MODE] [--stabilize]", 13, 10
usage_len equ $-usage_msg
banner_msg db "   _  __    __           ___   ______  ___", 13, 10
           db "  / |/ /__ / /___ ______/ _ | / __/  |/  /", 13, 10
           db " /    / -_) __/\\ \\ /___/ __ |_\\ \\/ /|_/ / ", 13, 10
           db "/_/|_/\\__/\\__//_\\_\\   /_/ |_/___/_/  /_/  ", 13, 10
           db 13, 10
banner_len equ $-banner_msg
closed_msg db " CLOSED", 13, 10
closed_len equ $-closed_msg
filtered_msg db " FILTERED", 13, 10
filtered_len equ $-filtered_msg
open_ttl_msg db " OPEN TTL="
open_ttl_len equ $-open_ttl_msg
open_win_msg db " WIN="
open_win_len equ $-open_win_msg
newline_msg db 13, 10
newline_len equ $-newline_msg
open_count_msg db "OPEN COUNT: "
open_count_len equ $-open_count_msg
open_ports_msg db "OPEN PORTS: "
open_ports_len equ $-open_ports_msg
none_msg db "none"
none_len equ $-none_msg
space_msg db " "
space_len equ $-space_msg
error_msg db "ERROR", 13, 10
error_len equ $-error_msg

hdrincl dd 1
timeout_ms dd 1000

src_port dw 40000
start_port dw 1
end_port dw 1000
src_port_be dw 0
dst_port_be dw 0

SECTION .bss
wsa_data resb 512
packet_buf resb 60
recv_buf resb 4096
out_buf resb 16
output_buf resb OUTPUT_BUF_SIZE
output_pos resq 1
cmd_buf resb 1024
sockaddr_dst resb 16
sockaddr_tmp resb 16
sockaddr_local resb 16
addrlen resd 1
sock_fd resq 1
stdout_handle resq 1
bytes_written resd 1
target_ip resd 1
source_ip resd 1
last_ttl resb 1
last_win resw 1
result_map resb 8192
open_count resd 1
engine_id resb 1
scan_mode resb 1
rate_value resd 1
rate_cycles resq 1
rate_min_cycles resq 1
rate_max_cycles resq 1
rate_enabled resb 1
last_send_tsc resq 1
tsc_hz resq 1
qpc_freq resq 1
qpc_start resq 1
qpc_end resq 1
tsc_start resq 1
stab_enabled resb 1
stab_sent resd 1
stab_recv resd 1
stab_timeout resd 1

SECTION .text
_start:
    mov qword [sock_fd], INVALID_SOCKET
    sub rsp, 40
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    add rsp, 40
    mov [stdout_handle], rax

    sub rsp, 40
    mov ecx, 0x0202
    lea rdx, [wsa_data]
    call WSAStartup
    add rsp, 40
    test eax, eax
    jne .error

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

    lea rdi, [cmd_buf]
    call next_token
    mov rdi, rdx
    call next_token
    test rax, rax
    jz .usage
    mov rdi, rax
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
    cmp byte [rsi], '-'
    jne .check_scan
    cmp byte [rsi+1], '-'
    jne .check_scan
    cmp byte [rsi+2], 'r'
    jne .check_scan
    cmp byte [rsi+3], 'a'
    jne .check_scan
    cmp byte [rsi+4], 't'
    jne .check_scan
    cmp byte [rsi+5], 'e'
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
    cmp byte [rsi], '-'
    jne .check_stabilize
    cmp byte [rsi+1], '-'
    jne .check_stabilize
    cmp byte [rsi+2], 's'
    jne .check_stabilize
    cmp byte [rsi+3], 'c'
    jne .check_stabilize
    cmp byte [rsi+4], 'a'
    jne .check_stabilize
    cmp byte [rsi+5], 'n'
    jne .check_stabilize
    cmp byte [rsi+6], 0
    jne .check_stabilize
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

.check_stabilize:
    cmp byte [rsi], '-'
    jne .arg_next
    cmp byte [rsi+1], '-'
    jne .arg_next
    cmp byte [rsi+2], 's'
    jne .arg_next
    cmp byte [rsi+3], 't'
    jne .arg_next
    cmp byte [rsi+4], 'a'
    jne .arg_next
    cmp byte [rsi+5], 'b'
    jne .arg_next
    cmp byte [rsi+6], 'i'
    jne .arg_next
    cmp byte [rsi+7], 'l'
    jne .arg_next
    cmp byte [rsi+8], 'i'
    jne .arg_next
    cmp byte [rsi+9], 'z'
    jne .arg_next
    cmp byte [rsi+10], 'e'
    jne .arg_next
    cmp byte [rsi+11], 0
    jne .arg_next
    mov byte [stab_enabled], 1
    jmp .arg_next

.arg_next:
    mov rdi, rdx
    jmp .arg_loop

.ports_ready:
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax
    mov byte [engine_id], ENGINE_SYN
    mov byte [scan_mode], SCAN_SYN
    lea rsi, [banner_msg]
    mov edx, banner_len
    call buf_write

    call get_local_ip
    test eax, eax
    jnz .error

    call init_rate

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

.scan_loop:
    cmp ecx, r15d
    ja .scan_done

    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    mov ax, [dst_port_be]
    call build_packet

    call rate_gate
    sub rsp, 56
    mov rcx, [sock_fd]
    lea rdx, [packet_buf]
    mov r8d, 40
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
    mov al, [rdx+13]
    mov bl, al
    mov dl, [scan_mode]
    cmp dl, SCAN_SYN
    je .classify_syn
    cmp dl, SCAN_ACK
    je .classify_ack
    cmp dl, SCAN_WINDOW
    je .classify_ack

.classify_flag:
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
    jmp .next_port

.next_port:
    call stabilize_step
    inc ecx
    jmp .scan_loop

.scan_done:
    call write_summary
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

; rsi=buf, edx=len
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

; rsi=src, edx=len
buf_write:
    mov r8, rsi
    mov r9, rdx
    mov rax, [output_pos]
    mov rcx, rax
    add rcx, r9
    cmp rcx, OUTPUT_BUF_SIZE
    ja .buf_flush
    cmp rcx, OUTPUT_FLUSH_THRESHOLD
    jae .buf_flush

.buf_write:
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
    jmp .buf_write

flush_output:
    mov rax, [output_pos]
    test rax, rax
    jz .flush_done
    lea rsi, [output_buf]
    mov edx, eax
    call write_stdout
    mov qword [output_pos], 0

.flush_done:
    ret

; inputs: ax=value
append_u16:
    movzx eax, ax
    lea rsi, [out_buf+6]
    xor rcx, rcx

.u16_digits:
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
    jnz .u16_digits

    mov edx, ecx
    call buf_write
    ret

; inputs: ax=port, r9=msg ptr, r10d=msg len
write_result:
    call append_u16
    mov rsi, r9
    mov edx, r10d
    call buf_write
    ret

; inputs: ax=port
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
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

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

rate_gate:
    cmp byte [rate_enabled], 0
    je .rate_done
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, [last_send_tsc]
    test r8, r8
    jz .rate_store

.rate_wait:
    mov r9, rax
    sub r9, r8
    cmp r9, [rate_cycles]
    jae .rate_store
    rdtsc
    shl rdx, 32
    or rax, rdx
    jmp .rate_wait

.rate_store:
    mov [last_send_tsc], rax

.rate_done:
    ret

stabilize_step:
    cmp byte [stab_enabled], 0
    je .stab_done
    cmp byte [rate_enabled], 0
    je .stab_done
    push rcx
    mov eax, [stab_sent]
    test eax, eax
    jz .stab_restore
    xor edx, edx
    mov ecx, 128
    div ecx
    test edx, edx
    jne .stab_restore
    mov eax, [stab_timeout]
    mov ecx, [stab_recv]
    lea edx, [ecx*2]
    cmp eax, edx
    ja .stab_slow
    lea edx, [eax*2]
    cmp ecx, edx
    ja .stab_fast
    jmp .stab_reset

.stab_slow:
    call slow_down
    jmp .stab_reset

.stab_fast:
    call speed_up

.stab_reset:
    mov dword [stab_sent], 0
    mov dword [stab_recv], 0
    mov dword [stab_timeout], 0

.stab_restore:
    pop rcx

.stab_done:
    ret

slow_down:
    mov rax, [rate_cycles]
    mov rcx, rax
    shr rcx, 2
    add rax, rcx
    mov rdx, [rate_max_cycles]
    test rdx, rdx
    jz .slow_store
    cmp rax, rdx
    jbe .slow_store
    mov rax, rdx

.slow_store:
    mov [rate_cycles], rax
    ret

speed_up:
    mov rax, [rate_cycles]
    mov rcx, rax
    shr rcx, 3
    sub rax, rcx
    mov rdx, [rate_min_cycles]
    test rdx, rdx
    jz .fast_store
    cmp rax, rdx
    jae .fast_store
    mov rax, rdx

.fast_store:
    mov [rate_cycles], rax
    ret

init_rate:
    mov eax, [rate_value]
    test eax, eax
    jnz .init_rate_do
    cmp byte [stab_enabled], 0
    je .init_rate_done
    mov dword [rate_value], 200000
    mov eax, [rate_value]

.init_rate_do:
    call calibrate_tsc
    mov ecx, [rate_value]
    mov rax, [tsc_hz]
    xor rdx, rdx
    div rcx
    mov [rate_cycles], rax
    mov byte [rate_enabled], 1
    cmp byte [stab_enabled], 0
    je .init_rate_done
    mov rax, [rate_cycles]
    mov rcx, rax
    shl rcx, 2
    mov [rate_max_cycles], rcx
    mov rcx, rax
    shr rcx, 2
    mov [rate_min_cycles], rcx

.init_rate_done:
    ret

calibrate_tsc:
    sub rsp, 40
    lea rcx, [qpc_freq]
    call QueryPerformanceFrequency
    add rsp, 40
    test eax, eax
    jz .calib_done

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

.calib_loop:
    sub rsp, 40
    lea rcx, [qpc_end]
    call QueryPerformanceCounter
    add rsp, 40
    mov rax, [qpc_end]
    sub rax, [qpc_start]
    cmp rax, r11
    jb .calib_loop
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

.calib_done:
    ret

; rdi -> command line string
; returns rax=token start or 0, rdx=next position
next_token:
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
    jne .noquote
    inc rdi
    mov rax, rdi

.scan_quote:
    mov al, [rdi]
    cmp al, 0
    je .done_quote
    cmp al, '"'
    je .term_quote
    inc rdi
    jmp .scan_quote

.term_quote:
    mov byte [rdi], 0
    inc rdi
    mov rdx, rdi
    ret

.done_quote:
    mov rdx, rdi
    ret

.noquote:
    mov rax, rdi

.scan:
    mov al, [rdi]
    cmp al, 0
    je .done
    cmp al, ' '
    je .term
    inc rdi
    jmp .scan

.term:
    mov byte [rdi], 0
    inc rdi

.done:
    mov rdx, rdi
    ret

.none:
    xor eax, eax
    mov rdx, rdi
    ret

; returns eax=0 on success
get_local_ip:
    sub rsp, 40
    mov ecx, AF_INET
    mov edx, SOCK_DGRAM
    mov r8d, IPPROTO_UDP
    call socket
    add rsp, 40
    cmp rax, INVALID_SOCKET
    je .get_ip_fail
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
    jne .get_ip_cleanup_fail

    mov dword [addrlen], 16
    sub rsp, 40
    mov rcx, rbx
    lea rdx, [sockaddr_local]
    lea r8, [addrlen]
    call getsockname
    add rsp, 40
    test eax, eax
    jne .get_ip_cleanup_fail

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    sub rsp, 40
    mov rcx, rbx
    call closesocket
    add rsp, 40
    xor eax, eax
    ret

.get_ip_cleanup_fail:
    sub rsp, 40
    mov rcx, rbx
    call closesocket
    add rsp, 40

.get_ip_fail:
    mov eax, 1
    ret
