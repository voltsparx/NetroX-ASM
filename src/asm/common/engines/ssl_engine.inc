
%ifndef SSL_ENGINE_INC
%define SSL_ENGINE_INC 1

; ------------------------------------------------------------
; TLS ClientHello (TCP)
; ------------------------------------------------------------
ssl_engine_run:
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
    lea  rsi, [tls_client_hello]
    mov  edx, tls_client_hello_len
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    mov  rax, SYS_RECVFROM
    mov  rdi, rbx
    lea  rsi, [recv_buf]
    mov  edx, 2048
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
tls_client_hello:
    db 0x16, 0x03, 0x01
    dw 0x00BB
    db 0x01
    db 0x00, 0x00, 0xB7
    db 0x03, 0x03
    times 32 db 0xAA
    db 0x00
    dw 0x0002
    dw 0x002F
    db 0x01
    db 0x00

tls_client_hello_len equ $-tls_client_hello

%endif
