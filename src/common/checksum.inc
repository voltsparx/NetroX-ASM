; ============================================================
; checksum.inc  -  IP, TCP, UDP, ICMP checksum routines
; All routines use one's complement sum over 16-bit words.
; All return ax = final checksum, byte-swapped for direct store
; into a little-endian packet buffer field.
; ============================================================

; ------------------------------------------------------------
; Helper macro: add one big-endian 16-bit word at [addr] to rax
; ------------------------------------------------------------
%macro ADD_WORD_BE 1
    movzx rbx, byte [%1]
    shl   rbx, 8
    movzx rdx, byte [%1+1]
    or    rbx, rdx
    add   rax, rbx
%endmacro

; ------------------------------------------------------------
; ip_checksum
; Input:  rdi -> IP header (exactly 20 bytes)
; Output: ax  = checksum ready to store at packet_buf+10
;
; Call with checksum field zeroed before calling.
; ------------------------------------------------------------
ip_checksum:
    xor  rax, rax
    mov  rcx, 10            ; 10 x 16-bit words = 20 bytes
    mov  rsi, rdi

.loop:
    movzx rbx, byte [rsi]
    shl   rbx, 8
    movzx rdx, byte [rsi+1]
    or    rbx, rdx
    add   rax, rbx
    add   rsi, 2
    loop  .loop

    ; Fold 32-bit sum into 16 bits
    mov  rbx, rax
    shr  rbx, 16
    and  eax, 0xFFFF
    add  eax, ebx
    mov  ebx, eax
    shr  ebx, 16
    add  eax, ebx
    not  ax
    xchg al, ah
    ret

; ------------------------------------------------------------
; tcp_checksum
; Input:  rdi -> packet_buf (IP header at 0, TCP header at 20)
;         Assumes TCP header is 20 bytes (no options), no payload.
; Output: ax  = checksum ready to store at packet_buf+36
;
; TCP pseudo-header:
;   src_ip (4) + dst_ip (4) + zero (1) + proto=6 (1) + tcp_len (2)
; ------------------------------------------------------------
tcp_checksum:
    xor rax, rax

    ; Pseudo-header: src IP
    ADD_WORD_BE rdi+12
    ADD_WORD_BE rdi+14
    ; Pseudo-header: dst IP
    ADD_WORD_BE rdi+16
    ADD_WORD_BE rdi+18
    ; Pseudo-header: zero + protocol (6)
    add rax, 0x0006
    ; Pseudo-header: TCP segment length = 20 (header, no payload)
    add rax, 0x0014

    ; TCP header: 10 x 16-bit words (20 bytes)
    mov  rcx, 10
    lea  rsi, [rdi+20]

.loop:
    movzx rbx, byte [rsi]
    shl   rbx, 8
    movzx rdx, byte [rsi+1]
    or    rbx, rdx
    add   rax, rbx
    add   rsi, 2
    loop  .loop

    ; Fold and invert
    mov  rbx, rax
    shr  rbx, 16
    and  eax, 0xFFFF
    add  eax, ebx
    mov  ebx, eax
    shr  ebx, 16
    add  eax, ebx
    not  ax
    xchg al, ah
    ret

; ------------------------------------------------------------
; udp_checksum
; Input:  rdi -> packet_buf (IP header at 0, UDP header at 20)
;         UDP header is 8 bytes, no payload.
; Output: ax  = checksum ready to store at packet_buf+26
;
; UDP pseudo-header:
;   src_ip (4) + dst_ip (4) + zero (1) + proto=17 (1) + udp_len (2)
; UDP length = 8 (header only)
; Checksum of 0x0000 is transmitted as 0xFFFF for UDP.
; For scanning purposes we transmit 0 (checksum disabled) which
; is valid - receiver skips the check.  This routine is provided
; for completeness when a real checksum is needed.
; ------------------------------------------------------------
udp_checksum:
    xor rax, rax

    ; Pseudo-header: src IP
    ADD_WORD_BE rdi+12
    ADD_WORD_BE rdi+14
    ; Pseudo-header: dst IP
    ADD_WORD_BE rdi+16
    ADD_WORD_BE rdi+18
    ; Pseudo-header: zero + protocol (17)
    add rax, 0x0011
    ; Pseudo-header: UDP segment length = 8
    add rax, 0x0008

    ; UDP header: 4 x 16-bit words (8 bytes)
    mov  rcx, 4
    lea  rsi, [rdi+20]

.loop:
    movzx rbx, byte [rsi]
    shl   rbx, 8
    movzx rdx, byte [rsi+1]
    or    rbx, rdx
    add   rax, rbx
    add   rsi, 2
    loop  .loop

    ; Fold and invert
    mov  rbx, rax
    shr  rbx, 16
    and  eax, 0xFFFF
    add  eax, ebx
    mov  ebx, eax
    shr  ebx, 16
    add  eax, ebx
    not  ax
    ; If result is 0x0000 after inversion, RFC 768 says send 0xFFFF
    test ax, ax
    jnz  .done
    mov  ax, 0xFFFF
.done:
    xchg al, ah
    ret

; ------------------------------------------------------------
; icmp_checksum
; Input:  rsi -> start of ICMP header
;         ecx = number of 16-bit words to sum (e.g. 20 for 40 bytes)
; Output: ax  = checksum ready to store at icmp_header+2
;
; Caller sets checksum field to 0 before calling.
; ------------------------------------------------------------
icmp_checksum:
    xor rax, rax

.loop:
    movzx rbx, byte [rsi]
    shl   rbx, 8
    movzx rdx, byte [rsi+1]
    or    rbx, rdx
    add   rax, rbx
    add   rsi, 2
    loop  .loop

    mov  rbx, rax
    shr  rbx, 16
    and  eax, 0xFFFF
    add  eax, ebx
    mov  ebx, eax
    shr  ebx, 16
    add  eax, ebx
    not  ax
    xchg al, ah
    ret

; ------------------------------------------------------------
; crc32c_compute
; Input:  rsi = data pointer, ecx = length
; Output: eax = CRC32c (Castagnoli)
; ------------------------------------------------------------
crc32c_compute:
    push rbx
    mov eax, 0xFFFFFFFF
.crc_loop:
    test ecx, ecx
    jz .crc_done
    mov bl, [rsi]
    xor al, bl
    mov edx, 8
.bit_loop:
    test eax, 1
    jz .shift
    shr eax, 1
    xor eax, 0x82F63B78
    jmp .bit_next
.shift:
    shr eax, 1
.bit_next:
    dec edx
    jnz .bit_loop
    inc rsi
    dec ecx
    jmp .crc_loop
.crc_done:
    not eax
    pop rbx
    ret
