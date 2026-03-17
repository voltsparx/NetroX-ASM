
%ifndef MDNS_ENGINE_INC
%define MDNS_ENGINE_INC 1

; ------------------------------------------------------------
; mDNS probe (UDP 5353)
; ------------------------------------------------------------
mdns_engine_run:
    push rbx

    mov  ax, 0xE914             ; 5353 big-endian
    mov  [dst_port_be], ax
    call build_udp_packet

    lea  rsi, [mdns_query]
    lea  rdi, [packet_buf+28]
    mov  ecx, mdns_query_len
    rep  movsb

    ; IP total length = 20 + 8 + payload
    mov  eax, mdns_query_len
    add  eax, 28
    mov  bx, ax
    xchg bl, bh
    mov  [packet_buf+2], bx

    ; UDP length = 8 + payload
    mov  eax, mdns_query_len
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
    mov  edx, mdns_query_len + 28
    xor  r10d, r10d
    lea  r8, [sockaddr_dst]
    mov  r9d, 16
    syscall

    pop  rbx
    ret

SECTION .data
mdns_query:
    ; Standard mDNS query for _services._dns-sd._udp.local PTR
    dw 0x0000        ; transaction id = 0
    dw 0x0000        ; flags
    dw 0x0100        ; questions = 1
    dw 0x0000        ; answers
    dw 0x0000        ; authority
    dw 0x0000        ; additional
    db 0x09, "_services"
    db 0x07, "_dns-sd"
    db 0x04, "_udp"
    db 0x05, "local"
    db 0x00
    dw 0x000c        ; PTR
    dw 0x0001        ; IN
mdns_query_len equ $ - mdns_query

%endif
