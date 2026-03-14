%ifndef PACKET_INC
%define PACKET_INC 1

%include "scan.inc"

; init_packet_template
; uses packet_buf, source_ip, target_ip, src_port_be
init_packet_template:
    lea rdi, [packet_buf]
    xor rax, rax
    mov rcx, 60/8
    rep stosq

    mov byte [packet_buf], 0x45
    mov byte [packet_buf+1], 0
    mov word [packet_buf+2], 0x2800
    mov word [packet_buf+4], 0x3412
    mov word [packet_buf+6], 0x0040
    mov byte [packet_buf+8], 64
    mov byte [packet_buf+9], 6
    mov word [packet_buf+10], 0
    mov eax, [source_ip]
    mov [packet_buf+12], eax
    mov eax, [target_ip]
    mov [packet_buf+16], eax

    lea rdi, [packet_buf]
    call ip_checksum
    mov [packet_buf+10], ax

    mov ax, [src_port_be]
    mov [packet_buf+20], ax
    mov dword [packet_buf+24], 0x78563412
    mov dword [packet_buf+28], 0
    mov byte [packet_buf+32], 0x50
    mov byte [packet_buf+33], 0x02
    mov word [packet_buf+34], 0xFFFF
    mov word [packet_buf+36], 0
    mov word [packet_buf+38], 0
    ret

; build_syn_packet
; expects dst_port_be set
build_syn_packet:
    mov ax, [dst_port_be]
    mov [packet_buf+22], ax
    mov [sockaddr_dst+2], ax
    mov bl, 0x02
    mov al, [scan_mode]
    cmp al, SCAN_SYN
    je .flags_ready
    cmp al, SCAN_ACK
    jne .check_fin
    mov bl, 0x10
    jmp .flags_ready

.check_fin:
    cmp al, SCAN_FIN
    jne .check_null
    mov bl, 0x01
    jmp .flags_ready

.check_null:
    cmp al, SCAN_NULL
    jne .check_xmas
    mov bl, 0x00
    jmp .flags_ready

.check_xmas:
    cmp al, SCAN_XMAS
    jne .check_window
    mov bl, 0x29
    jmp .flags_ready

.check_window:
    cmp al, SCAN_WINDOW
    jne .check_maimon
    mov bl, 0x10
    jmp .flags_ready

.check_maimon:
    cmp al, SCAN_MAIMON
    jne .flags_ready
    mov bl, 0x11

.flags_ready:
    mov [packet_buf+33], bl
    mov word [packet_buf+36], 0
    lea rdi, [packet_buf]
    call tcp_checksum
    mov [packet_buf+36], ax
    ret

%endif
