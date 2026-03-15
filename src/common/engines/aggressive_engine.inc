; ============================================================
; aggressive_engine.inc - scan engine (stub)
; ============================================================

%ifndef AGGRESSIVE_ENGINE_INC
%define AGGRESSIVE_ENGINE_INC 1

; ------------------------------------------------------------
; aggressive_run
; Enables OS + version + script + traceroute (placeholder)
; ------------------------------------------------------------
aggressive_run:
    mov byte [os_enabled], 1
    mov byte [version_enabled], 1
    mov byte [script_mode], 1
    mov byte [aggressive_mode], 1
    jmp scan_loop_entry

; ------------------------------------------------------------
; aggressive_post
; Simple TCP SYN traceroute to port 80
; ------------------------------------------------------------
aggressive_post:
    push rbx
    push r12
    push r13
    mov ecx, 1
.ttl_loop:
    cmp ecx, 30
    jae .done
    mov word [dst_port_be], 0x5000
    mov [sockaddr_dst+2], word 0x5000
    mov byte [scan_mode], SCAN_SYN
    call build_syn_packet
    mov byte [packet_buf+8], cl
    mov word [packet_buf+10], 0
    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

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
    mov r10d, 2000
    syscall
    test rax, rax
    jle .next_ttl

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .next_ttl

    lea rsi, [recv_buf]
    ; ICMP time exceeded
    cmp byte [rsi+9], 1
    jne .check_synack
    cmp byte [rsi+20], 11
    jne .check_synack
    mov eax, [rsi+12]
    call ip_print_addr
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    jmp .next_ttl
.check_synack:
    cmp byte [rsi+9], 6
    jne .next_ttl
    mov eax, [rsi+12]
    call ip_print_addr
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    jmp .done

.next_ttl:
    inc ecx
    jmp .ttl_loop
.done:
    pop r13
    pop r12
    pop rbx
    ret

%endif
