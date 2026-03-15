; ============================================================
; icmp_nm_engine.inc - scan engine (stub)
; ============================================================

%ifndef ICMP_NM_ENGINE_INC
%define ICMP_NM_ENGINE_INC 1

; ------------------------------------------------------------
; icmp_nm_run
; ICMP Address Mask request (type 17)
; ------------------------------------------------------------
icmp_nm_run:
    push rbx

    ; Build IP header
    mov byte [packet_buf+0], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x1C00    ; total length 28
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

    ; ICMP Address Mask request (8 bytes)
    mov byte [packet_buf+20], 17
    mov byte [packet_buf+21], 0
    mov word [packet_buf+22], 0
    mov word [packet_buf+24], 0
    mov word [packet_buf+26], 0
    lea rsi, [packet_buf+20]
    mov ecx, 4
    call icmp_checksum
    mov [packet_buf+22], ax

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 28
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
    jle .nm_filtered

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .nm_filtered

    ; check ICMP Address Mask Reply (type 18)
    lea rsi, [recv_buf]
    cmp byte [rsi+9], 1
    jne .nm_filtered
    cmp byte [rsi+20], 18
    jne .nm_filtered

    mov ax, 0
    call write_open_intel
    jmp .done

.nm_filtered:
    mov ax, 0
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    inc dword [filtered_count]

.done:
    pop rbx
    ret

%endif
