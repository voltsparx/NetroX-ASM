; ============================================================
; sctp_echo_engine.inc - scan engine (stub)
; ============================================================

%ifndef SCTP_ECHO_ENGINE_INC
%define SCTP_ECHO_ENGINE_INC 1

SECTION .text

; ------------------------------------------------------------
; sctp_echo_run
; SCTP COOKIE-ECHO scan
; ------------------------------------------------------------
sctp_echo_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov r14d, r15d
    sub r14d, ecx
    inc r14d
    xor ebx, ebx

.loop:
    cmp ebx, r14d
    jae .done
    mov rdi, rbx
    mov rsi, r14
    call blackrock_permute
    movzx ecx, word [start_port]
    add ecx, eax

    call sctp_build_cookie
    call sctp_echo_send_and_classify

    inc ebx
    jmp .loop

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ------------------------------------------------------------
; sctp_build_cookie
; ecx = dst port
; ------------------------------------------------------------
sctp_build_cookie:
    push rax
    push rbx

    ; IP header (20 bytes)
    mov byte [packet_buf+0], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x4400    ; 68 bytes
    rdtsc
    mov word [packet_buf+4], ax
    mov word [packet_buf+6], 0
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], SCTP_PROTO
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax
    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    ; SCTP common header (12 bytes)
    call xorshift64_next
    mov ax, ax
    mov [packet_buf+20], ax
    mov ax, cx
    xchg al, ah
    mov [packet_buf+22], ax
    mov dword [packet_buf+24], 0
    mov dword [packet_buf+28], 0

    ; COOKIE-ECHO chunk
    mov byte [packet_buf+32], SCTP_CHUNK_COOKIE_ECHO
    mov byte [packet_buf+33], 0
    mov word [packet_buf+34], 0x2400  ; length 36
    lea rdi, [packet_buf+36]
    mov ecx, 32
.cookie_fill:
    call xorshift64_next
    mov [rdi], eax
    add rdi, 4
    sub ecx, 4
    jg .cookie_fill

    ; checksum
    lea rsi, [packet_buf+20]
    mov ecx, 48
    call crc32c_compute
    mov [packet_buf+28], eax

    pop rbx
    pop rax
    ret

; ------------------------------------------------------------
; sctp_echo_send_and_classify
; ------------------------------------------------------------
sctp_echo_send_and_classify:
    push rax
    push rbx

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 68
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
    jle .filtered

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .filtered

    lea rsi, [recv_buf]
    cmp byte [rsi+9], SCTP_PROTO
    jne .filtered
    mov al, [rsi+32]
    cmp al, 11              ; COOKIE-ACK
    je .open
    cmp al, 6               ; ABORT
    je .closed
    jmp .filtered

.open:
    mov ax, cx
    call record_open
    mov ax, cx
    call write_open_intel
    jmp .done
.closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    inc dword [closed_count]
    jmp .done
.filtered:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    inc dword [filtered_count]
.done:
    pop rbx
    pop rax
    ret

%endif
