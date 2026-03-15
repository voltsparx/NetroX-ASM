%ifndef TCP_ENGINE_INC
%define TCP_ENGINE_INC 1

%include "scan.inc"

; ============================================================
; build_syn_packet
; ============================================================
build_syn_packet:
    mov  ax, [dst_port_be]
    mov  [packet_buf+22], ax
    mov  [sockaddr_dst+2], ax

    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax

    mov  rdi, [current_scan_ip]
    call cookie_generate
    mov  [packet_buf+24], eax

    mov  bl, 0x02
    mov  al, [scan_mode]
    cmp  al, SCAN_SYN
    je   .flags_ready
    cmp  al, SCAN_ACK
    jne  .check_fin
    mov  bl, 0x10
    jmp  .flags_ready
.check_fin:
    cmp  al, SCAN_FIN
    jne  .check_null
    mov  bl, 0x01
    jmp  .flags_ready
.check_null:
    cmp  al, SCAN_NULL
    jne  .check_xmas
    mov  bl, 0x00
    jmp  .flags_ready
.check_xmas:
    cmp  al, SCAN_XMAS
    jne  .check_window
    mov  bl, 0x29
    jmp  .flags_ready
.check_window:
    cmp  al, SCAN_WINDOW
    jne  .check_maimon
    mov  bl, 0x10
    jmp  .flags_ready
.check_maimon:
    cmp  al, SCAN_MAIMON
    jne  .flags_ready
    mov  bl, 0x11

.flags_ready:
    mov  [packet_buf+33], bl

    mov  word [packet_buf+36], 0
    lea  rdi, [packet_buf]
    call tcp_checksum
    mov  [packet_buf+36], ax
    ret

; ============================================================
; build_udp_packet
; ============================================================
build_udp_packet:
    mov  byte [packet_buf+9],  17
    mov  word [packet_buf+2],  0x1C00
    mov  ax, [packet_buf+4]
    inc  ax
    mov  [packet_buf+4], ax
    mov  word [packet_buf+10], 0
    lea  rdi, [packet_buf]
    call ip_checksum
    mov  [packet_buf+10], ax
    mov  ax, [src_port_be]
    mov  [packet_buf+20], ax
    mov  ax, [dst_port_be]
    mov  [packet_buf+22], ax
    mov  [sockaddr_dst+2], ax
    mov  word [packet_buf+24], 0x0800
    mov  word [packet_buf+26], 0
    ret

%endif
