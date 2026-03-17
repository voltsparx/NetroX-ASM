
%ifndef HTTP_ENGINE_INC
%define HTTP_ENGINE_INC 1

; ------------------------------------------------------------
; HTTP banner grab (TCP)
; ------------------------------------------------------------
http_engine_run:
    push rbx

    ; open socket
    mov  rax, SYS_SOCKET
    mov  rdi, AF_INET
    mov  rsi, SOCK_STREAM
    xor  rdx, rdx
    syscall
    test rax, rax
    js .done
    mov  rbx, rax

    ; connect
    mov  rax, SYS_CONNECT
    mov  rdi, rbx
    lea  rsi, [sockaddr_dst]
    mov  rdx, 16
    syscall
    test rax, rax
    js .close

    ; send GET
    mov  rax, SYS_SENDTO
    mov  rdi, rbx
    lea  rsi, [http_get_request]
    mov  edx, http_get_request_len
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall

    ; recv (best-effort)
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
http_get_request:
    db "GET / HTTP/1.0", 13, 10
    db "User-Agent: NetroX-ASC/2.0", 13, 10
    db "Connection: close", 13, 10, 13, 10
http_get_request_len equ $-http_get_request

%endif
