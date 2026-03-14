BITS 64
GLOBAL _start

%include "../common/constants.inc"
%include "../common/parse.inc"
%include "../common/checksum.inc"

%define OUTPUT_BUF_SIZE 131072
%define OUTPUT_FLUSH_THRESHOLD 98304

SECTION .data
usage_msg db "Usage: netx-asm <target_ip> [-p port|start-end|-]", 10
usage_len equ $-usage_msg
closed_msg db " CLOSED", 10
closed_len equ $-closed_msg
filtered_msg db " FILTERED", 10
filtered_len equ $-filtered_msg
open_ttl_msg db " OPEN TTL="
open_ttl_len equ $-open_ttl_msg
open_win_msg db " WIN="
open_win_len equ $-open_win_msg
newline_msg db 10
newline_len equ $-newline_msg
error_msg db "ERROR", 10
error_len equ $-error_msg

hdrincl dd 1
timeout_timeval dq 1, 0

src_port dw 40000
dst_port dw 0
start_port dw 1
end_port dw 1000
src_port_be dw 0
dst_port_be dw 0

SECTION .bss
packet_buf resb 60
recv_buf resb 4096
out_buf resb 16
output_buf resb OUTPUT_BUF_SIZE
output_pos resq 1
sockaddr_dst resb 16
sockaddr_tmp resb 16
sockaddr_local resb 16
addrlen resd 1
raw_fd resq 1
epoll_fd resq 1
target_ip resd 1
source_ip resd 1
last_ttl resb 1
last_win resw 1
epoll_event resb 16
epoll_out resb 16

SECTION .text
_start:
    xor r12d, r12d

    mov rbx, rsp
    mov rax, [rbx]
    cmp rax, 2
    jb .usage

    mov rdi, [rbx+16]
    call parse_ip
    test eax, eax
    jz .usage
    mov [target_ip], eax

    cmp qword [rbx], 4
    jl .ports_ready
    mov rsi, [rbx+24]
    cmp byte [rsi], '-'
    jne .ports_ready
    cmp byte [rsi+1], 'p'
    jne .ports_ready
    cmp byte [rsi+2], 0
    jne .ports_ready
    mov rdi, [rbx+32]
    cmp byte [rdi], '-'
    jne .parse_range
    cmp byte [rdi+1], 0
    jne .parse_range
    mov word [start_port], 1
    mov word [end_port], 65535
    jmp .ports_ready

.parse_range:
    call parse_port_range
    test ax, ax
    jz .usage
    mov [start_port], ax
    mov [end_port], dx

.ports_ready:
    mov ax, [src_port]
    xchg al, ah
    mov [src_port_be], ax

    call get_local_ip
    test eax, eax
    jnz .error

    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_RAW
    mov rdx, IPPROTO_TCP
    syscall
    test rax, rax
    js .error
    mov [raw_fd], rax

    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, IPPROTO_IP
    mov rdx, IP_HDRINCL
    lea r10, [hdrincl]
    mov r8, 4
    syscall
    test rax, rax
    js .error

    mov rax, SYS_SETSOCKOPT
    mov rdi, [raw_fd]
    mov rsi, SOL_SOCKET
    mov rdx, SO_RCVTIMEO
    lea r10, [timeout_timeval]
    mov r8, 16
    syscall
    test rax, rax
    js .error

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

    lea rdi, [packet_buf]
    xor rax, rax
    mov rcx, 60/8
    rep stosq

    mov byte [packet_buf], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x2800
    mov word [packet_buf+4], 0x3412
    mov word [packet_buf+6], 0x0040
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], 6
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax

    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    mov ax, [src_port_be]
    mov [packet_buf+20], ax
    mov dword [packet_buf+24], 0x78563412
    mov dword [packet_buf+28], 0
    mov byte [packet_buf+32], 0x50
    mov byte [packet_buf+33], 0x02
    mov word [packet_buf+34], 0xFFFF
    mov word [packet_buf+36], 0
    mov word [packet_buf+38], 0

    mov word [sockaddr_dst], AF_INET
    mov eax, [target_ip]
    mov [sockaddr_dst+4], eax

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]

.scan_loop:
    cmp ecx, r15d
    ja .exit

    mov ax, cx
    mov [dst_port], ax
    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    mov ax, [dst_port_be]
    mov [packet_buf+22], ax
    mov [sockaddr_dst+2], ax

    mov word [packet_buf+36], 0
    lea rdi, [packet_buf]
    call tcp_checksum
    mov [packet_buf+36], ax

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov rdx, 40
    xor r10, r10
    lea r8, [sockaddr_dst]
    mov r9, 16
    syscall
    test rax, rax
    js .error

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
    mov al, [rdx+13]
    mov bl, al
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
    mov ax, cx
    call write_open_intel
    jmp .next_port

.report_closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    jmp .next_port

.report_filtered:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    jmp .next_port

.next_port:
    inc ecx
    jmp .scan_loop

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
    mov rax, [epoll_fd]
    test rax, rax
    jz .exit_close_raw
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall

.exit_close_raw:
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
    mov rdi, 1
    lea rsi, [output_buf]
    mov rdx, rax
    mov rax, SYS_WRITE
    syscall
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
    mov r9d, 0xCCCCCCCD
    mul r9d
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

; inputs: ax=port, uses last_ttl/last_win
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

; returns eax = 0 on success, 1 on failure
get_local_ip:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .get_ip_fail
    mov rbx, rax

    mov word [sockaddr_tmp], AF_INET
    mov word [sockaddr_tmp+2], 0x3500
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    mov rax, SYS_CONNECT
    mov rdi, rbx
    lea rsi, [sockaddr_tmp]
    mov rdx, 16
    syscall
    test rax, rax
    js .get_ip_cleanup_fail

    mov dword [addrlen], 16
    mov rax, SYS_GETSOCKNAME
    mov rdi, rbx
    lea rsi, [sockaddr_local]
    lea rdx, [addrlen]
    syscall
    test rax, rax
    js .get_ip_cleanup_fail

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    xor eax, eax
    ret

.get_ip_cleanup_fail:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall

.get_ip_fail:
    mov eax, 1
    ret
