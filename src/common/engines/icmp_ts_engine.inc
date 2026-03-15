; ============================================================
; icmp_ts_engine.inc - scan engine (stub)
; ============================================================

%ifndef ICMP_TS_ENGINE_INC
%define ICMP_TS_ENGINE_INC 1

; ------------------------------------------------------------
; icmp_ts_run
; ICMP Timestamp request (type 13)
; ------------------------------------------------------------
icmp_ts_run:
    push rbx

    ; Build IP header
    mov byte [packet_buf+0], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x2800    ; total length 40
    rdtsc
    mov word [packet_buf+4], ax
    mov word [packet_buf+6], 0
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], 1
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax
    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    ; ICMP Timestamp request (20 bytes)
    mov byte [packet_buf+20], 13
    mov byte [packet_buf+21], 0
    mov word [packet_buf+22], 0
    mov word [packet_buf+24], 0
    mov word [packet_buf+26], 0
    mov qword [packet_buf+28], 0
    mov qword [packet_buf+36], 0
    lea rsi, [packet_buf+20]
    mov ecx, 10
    call icmp_checksum
    mov [packet_buf+22], ax

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 40
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
    jle .ts_filtered

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .ts_filtered

    ; check ICMP Timestamp Reply (type 14)
    lea rsi, [recv_buf]
    cmp byte [rsi+9], 1
    jne .ts_filtered
    cmp byte [rsi+20], 14
    jne .ts_filtered

    mov ax, 0
    call write_open_intel
    jmp .done

.ts_filtered:
    mov ax, 0
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    inc dword [filtered_count]

.done:
    pop rbx
    ret

%endif
