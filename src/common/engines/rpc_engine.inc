; ============================================================
; rpc_engine.inc - scan engine (stub)
; ============================================================

%ifndef RPC_ENGINE_INC
%define RPC_ENGINE_INC 1

SECTION .rodata
rpc_dump_req:
    dd 0x12345678         ; XID
    dd 0x00000000         ; CALL
    dd 0x00000002         ; RPC ver
    dd 0x000186A0         ; prog 100000
    dd 0x00000002         ; ver 2
    dd 0x00000004         ; proc 4 (DUMP)
    dd 0x00000000         ; AUTH_NULL
    dd 0x00000000         ; AUTH_NULL
rpc_dump_len equ $ - rpc_dump_req

SECTION .text

; ------------------------------------------------------------
; rpc_run
; UDP portmapper DUMP probe on port 111
; ------------------------------------------------------------
rpc_run:
    push rbx

    ; build IP header
    mov byte [packet_buf+0], 0x45
    mov byte [packet_buf+1], 0
    mov ax, 20+8+rpc_dump_len
    xchg al, ah
    mov [packet_buf+2], ax
    rdtsc
    mov word [packet_buf+4], ax
    mov word [packet_buf+6], 0
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], 17
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax
    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    ; UDP header
    mov word [packet_buf+20], 0x3500   ; src port 53 (arbitrary)
    mov word [packet_buf+22], 0x6F00   ; dst port 111
    mov ax, 8+rpc_dump_len
    xchg al, ah
    mov [packet_buf+24], ax
    mov word [packet_buf+26], 0

    ; payload
    lea rsi, [rpc_dump_req]
    lea rdi, [packet_buf+28]
    mov ecx, rpc_dump_len
    rep movsb

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 20+8+rpc_dump_len
    xor r10d, r10d
    lea r8, [sockaddr_dst]
    mov r9d, 16
    syscall

    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 1000
    syscall
    test rax, rax
    jle .done

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .done

    ; mark port 111 open
    mov ax, 111
    call record_open
    mov ax, 111
    call write_open_intel

.done:
    pop rbx
    ret

%endif
