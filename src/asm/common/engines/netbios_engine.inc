%ifndef NETBIOS_ENGINE_INC
%define NETBIOS_ENGINE_INC 1

netbios_engine_run:
    ; Minimal NBNS query send (no parse yet)
    push rax
    push rbx
    push rcx
    mov  byte [engine_id], ENGINE_UDP
    mov  ax, 0x8900
    mov  [dst_port_be], ax
    call build_udp_packet

    ; copy payload after UDP header
    lea  rdi, [packet_buf+28]
    lea  rsi, [nbns_query_buf]
    mov  ecx, nbns_query_len
    rep  movsb

    ; update lengths
    mov  ax, nbns_query_len
    add  ax, 8
    xchg al, ah
    mov  [packet_buf+24], ax      ; UDP length
    mov  ax, nbns_query_len
    add  ax, 28
    xchg al, ah
    mov  [packet_buf+2], ax       ; IP total length

    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax

    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 28
    add  edx, nbns_query_len
    xor  r10d, r10d
    lea  r8,  [sockaddr_dst]
    mov  r9d, 16
    syscall

    pop  rcx
    pop  rbx
    pop  rax
    ret

SECTION .data
nbns_query_buf:
    dw 0xA840
    dw 0x0000
    dw 0x0100
    dw 0x0000
    dw 0x0000
    dw 0x0000
    db 0x20
    db "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0
    dw 0x2100
    dw 0x0100
nbns_query_len equ $-nbns_query_buf

%endif
