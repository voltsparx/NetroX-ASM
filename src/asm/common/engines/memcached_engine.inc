
%ifndef MEMCACHED_ENGINE_INC
%define MEMCACHED_ENGINE_INC 1

; ------------------------------------------------------------
; Memcached version (TCP)
; ------------------------------------------------------------
memcached_engine_run:
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
    lea  rsi, [memc_version]
    mov  edx, memc_version_len
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
memc_version:     db "version\r\n"
memc_version_len  equ $-memc_version

%endif
