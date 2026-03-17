
%ifndef NTP_ENGINE_INC
%define NTP_ENGINE_INC 1

; ------------------------------------------------------------
; NTP client request (UDP 123)
; ------------------------------------------------------------
ntp_engine_run:
    push rbx

    mov  ax, 0x7B00             ; 123 big-endian
    mov  [dst_port_be], ax
    call build_udp_packet

    lea  rsi, [ntp_request]
    lea  rdi, [packet_buf+28]
    mov  ecx, ntp_request_len
    rep  movsb

    mov  eax, ntp_request_len
    add  eax, 28
    mov  bx, ax
    xchg bl, bh
    mov  [packet_buf+2], bx

    mov  eax, ntp_request_len
    add  eax, 8
    mov  bx, ax
    xchg bl, bh
    mov  [packet_buf+24], bx
    mov  word [packet_buf+26], 0

    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax

    mov  rax, SYS_SENDTO
    mov  rdi, [send_fd]
    lea  rsi, [packet_buf]
    mov  edx, ntp_request_len + 28
    xor  r10d, r10d
    lea  r8, [sockaddr_dst]
    mov  r9d, 16
    syscall

    pop  rbx
    ret

SECTION .data
ntp_request:
    db 0x1B
    times 47 db 0
ntp_request_len equ $ - ntp_request

%endif
