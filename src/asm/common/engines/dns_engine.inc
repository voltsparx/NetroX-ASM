
%ifndef DNS_ENGINE_INC
%define DNS_ENGINE_INC 1

; ------------------------------------------------------------
; DNS version.bind query (UDP 53)
; ------------------------------------------------------------
dns_engine_run:
    push rbx

    mov  ax, 0x3500             ; 53 big-endian
    mov  [dst_port_be], ax
    call build_udp_packet

    lea  rsi, [dns_version_query]
    lea  rdi, [packet_buf+28]
    mov  ecx, dns_version_query_len
    rep  movsb

    mov  eax, dns_version_query_len
    add  eax, 28
    mov  bx, ax
    xchg bl, bh
    mov  [packet_buf+2], bx

    mov  eax, dns_version_query_len
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
    mov  edx, dns_version_query_len + 28
    xor  r10d, r10d
    lea  r8, [sockaddr_dst]
    mov  r9d, 16
    syscall

    pop  rbx
    ret

SECTION .data
dns_version_query:
    dw 0x1234        ; transaction id
    dw 0x0100        ; flags: standard query
    dw 0x0001        ; questions: 1
    dw 0x0000        ; answers
    dw 0x0000        ; authority
    dw 0x0000        ; additional
    db 0x07, "version", 0x04, "bind", 0x00
    dw 0x0010        ; type TXT
    dw 0x0003        ; class CHAOS

dns_version_query_len equ $ - dns_version_query

%endif
