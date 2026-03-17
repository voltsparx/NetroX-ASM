
%ifndef SNMP_ENGINE_INC
%define SNMP_ENGINE_INC 1

; ------------------------------------------------------------
; SNMP GetRequest (UDP 161)
; ------------------------------------------------------------
snmp_engine_run:
    push rbx

    mov  ax, 0xA100             ; 161 big-endian
    mov  [dst_port_be], ax
    call build_udp_packet

    lea  rsi, [snmp_get_sysdescr]
    lea  rdi, [packet_buf+28]
    mov  ecx, snmp_get_sysdescr_len
    rep  movsb

    mov  eax, snmp_get_sysdescr_len
    add  eax, 28
    mov  bx, ax
    xchg bl, bh
    mov  [packet_buf+2], bx

    mov  eax, snmp_get_sysdescr_len
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
    mov  edx, snmp_get_sysdescr_len + 28
    xor  r10d, r10d
    lea  r8, [sockaddr_dst]
    mov  r9d, 16
    syscall

    pop  rbx
    ret

SECTION .data
snmp_get_sysdescr:
    db 0x30, 0x26             ; SEQUENCE, length 38
    db 0x02, 0x01, 0x01       ; version: INTEGER 1 (v2c)
    db 0x04, 0x06             ; community: OCTET STRING, length 6
    db "public"
    db 0xA0, 0x19             ; GetRequest PDU, length 25
    db 0x02, 0x01, 0x01       ; request-id: 1
    db 0x02, 0x01, 0x00       ; error-status: 0
    db 0x02, 0x01, 0x00       ; error-index: 0
    db 0x30, 0x0E             ; varbind list
    db 0x30, 0x0C             ; varbind
    db 0x06, 0x08             ; OID, length 8
    db 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00
    db 0x05, 0x00             ; value: NULL
snmp_get_sysdescr_len equ $ - snmp_get_sysdescr

%endif
