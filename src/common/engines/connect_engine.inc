; ============================================================
; connect_engine.inc - scan engine (stub)
; ============================================================

%ifndef CONNECT_ENGINE_INC
%define CONNECT_ENGINE_INC 1

; ------------------------------------------------------------
; connect_run
; TCP connect() scan using SOCK_STREAM
; ------------------------------------------------------------
connect_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; default timeout = 3s if not set
    mov al, [connect_timeo]
    test al, al
    jnz .timeo_set
    mov byte [connect_timeo], 3
.timeo_set:

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]

.conn_loop:
    cmp ecx, r15d
    ja  .conn_done

    ; open socket
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    xor rdx, rdx
    syscall
    test rax, rax
    js .conn_next
    mov [connect_fd], rax

    ; set timeouts (SO_SNDTIMEO / SO_RCVTIMEO)
    sub rsp, 16
    movzx eax, byte [connect_timeo]
    mov [rsp], rax       ; tv_sec
    xor rax, rax
    mov [rsp+8], rax     ; tv_usec
    mov rax, SYS_SETSOCKOPT
    mov rdi, [connect_fd]
    mov rsi, SOL_SOCKET
    mov rdx, SO_SNDTIMEO
    mov r10, rsp
    mov r8d, 16
    syscall
    mov rax, SYS_SETSOCKOPT
    mov rdi, [connect_fd]
    mov rsi, SOL_SOCKET
    mov rdx, SO_RCVTIMEO
    mov r10, rsp
    mov r8d, 16
    syscall
    add rsp, 16

    ; update port in sockaddr_dst
    mov ax, cx
    xchg al, ah
    mov [sockaddr_dst+2], ax

    ; connect
    mov rax, SYS_CONNECT
    mov rdi, [connect_fd]
    lea rsi, [sockaddr_dst]
    mov rdx, 16
    syscall
    test rax, rax
    jz .conn_open

    ; error in -errno (Linux)
    neg rax
    cmp eax, 111          ; ECONNREFUSED
    je  .conn_closed
    cmp eax, 110          ; ETIMEDOUT
    je  .conn_filtered
    jmp .conn_filtered

.conn_open:
    mov ax, cx
    call record_open
    mov ax, cx
    call write_open_intel
    jmp .conn_close

.conn_closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    inc dword [closed_count]
    jmp .conn_close

.conn_filtered:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    inc dword [filtered_count]

.conn_close:
    mov rax, SYS_CLOSE
    mov rdi, [connect_fd]
    syscall

.conn_next:
    inc ecx
    jmp .conn_loop

.conn_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%endif
