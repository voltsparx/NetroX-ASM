
%ifndef SMB_ENGINE_INC
%define SMB_ENGINE_INC 1

; ------------------------------------------------------------
; SMB negotiate (TCP)
; ------------------------------------------------------------
smb_engine_run:
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
    lea  rsi, [smb_negotiate_req]
    mov  edx, smb_negotiate_req_len
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
smb_negotiate_req:
    db 0x00
    db 0x00, 0x00, 0x54
    db 0xFF, 0x53, 0x4D, 0x42
    db 0x72
    times 4 db 0x00
    db 0x18
    dw 0x0001
    times 12 db 0x00
    dw 0x00
    dw 0xFF
    dw 0x00
    dw 0x00
    db 0x00
    dw 0x0C
    db 0x02, "NT LM 0.12", 0x00
smb_negotiate_req_len equ $-smb_negotiate_req

%endif
