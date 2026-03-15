; ============================================================
; iproto_engine.inc - scan engine (stub)
; ============================================================

%ifndef IPROTO_ENGINE_INC
%define IPROTO_ENGINE_INC 1

; ------------------------------------------------------------
; iproto_run
; IP protocol scan (0..255)
; ------------------------------------------------------------
iproto_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    xor ebx, ebx            ; blackrock index
    mov r14d, 256

.proto_loop:
    cmp ebx, r14d
    jae .proto_done

    mov rdi, rbx
    mov rsi, r14
    call blackrock_permute
    movzx ecx, al           ; protocol number 0..255

    ; Build minimal IP header (20 bytes) in packet_buf
    mov byte [packet_buf+0], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x1400   ; total length 20 (big-endian)
    rdtsc
    mov word [packet_buf+4], ax
    mov word [packet_buf+6], 0
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], cl
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax
    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    ; send
    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 20
    xor r10d, r10d
    lea r8, [sockaddr_dst]
    mov r9d, 16
    syscall

    ; wait for response
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 1000
    syscall
    test rax, rax
    jle .proto_filtered

    ; recv
    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .proto_filtered

    ; check ICMP protocol unreachable (type 3, code 2)
    lea rsi, [recv_buf]
    cmp byte [rsi+9], 1
    jne .proto_open
    cmp byte [rsi+20], 3
    jne .proto_open
    cmp byte [rsi+21], 2
    jne .proto_open
    jmp .proto_closed

.proto_open:
    mov byte [iproto_results+rcx], 1
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [open_msg]
    mov edx, open_msg_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    jmp .proto_next

.proto_closed:
    mov byte [iproto_results+rcx], 0
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [closed_msg]
    mov edx, closed_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    jmp .proto_next

.proto_filtered:
    mov byte [iproto_results+rcx], 2
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [filtered_msg]
    mov edx, filtered_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

.proto_next:
    inc ebx
    jmp .proto_loop

.proto_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%endif
