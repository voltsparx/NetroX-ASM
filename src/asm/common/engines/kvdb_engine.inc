
%ifndef KVDB_ENGINE_INC
%define KVDB_ENGINE_INC 1

; ------------------------------------------------------------
; Redis PING/INFO (TCP)
; ------------------------------------------------------------
redis_engine_run:
    push rbx

    mov  rax, SYS_SOCKET
    mov  rdi, AF_INET
    mov  rsi, SOCK_STREAM
    xor  rdx, rdx
    syscall
    test rax, rax
    js .done
    mov  rbx, rax

    mov  rax, SYS_CONNECT
    mov  rdi, rbx
    lea  rsi, [sockaddr_dst]
    mov  rdx, 16
    syscall
    test rax, rax
    js .close

    mov  rax, SYS_SENDTO
    mov  rdi, rbx
    lea  rsi, [redis_ping]
    mov  edx, redis_ping_len
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    mov  rax, SYS_RECVFROM
    mov  rdi, rbx
    lea  rsi, [recv_buf]
    mov  edx, 1024
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    mov  rax, SYS_SENDTO
    mov  rdi, rbx
    lea  rsi, [redis_info]
    mov  edx, redis_info_len
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    mov  rax, SYS_RECVFROM
    mov  rdi, rbx
    lea  rsi, [recv_buf]
    mov  edx, 1024
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

.close:
    mov  rax, SYS_CLOSE
    mov  rdi, rbx
    syscall
.done:
    pop  rbx
    ret

SECTION .data
redis_ping:       db "*1\r\n$4\r\nPING\r\n"
redis_ping_len    equ $-redis_ping
redis_info:       db "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"
redis_info_len    equ $-redis_info

%endif
