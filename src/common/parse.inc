; parse_ip
; rdi -> null-terminated IPv4 string
; returns eax = host-order IPv4, or 0 on error
%include "scan.inc"

parse_ip:
    push rbx
    xor eax, eax
    xor r8d, r8d
    xor r9d, r9d

.parse_ip_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_ip_last
    cmp bl, '.'
    je .parse_ip_store
    sub bl, '0'
    cmp bl, 9
    ja .parse_ip_invalid
    imul r8d, r8d, 10
    add r8d, ebx
    inc rdi
    jmp .parse_ip_loop

.parse_ip_store:
    cmp r8d, 255
    ja .parse_ip_invalid
    mov ebx, r8d
    mov ecx, r9d
    shl ecx, 3
    shl ebx, cl
    or eax, ebx
    inc r9d
    xor r8d, r8d
    inc rdi
    jmp .parse_ip_loop

.parse_ip_last:
    cmp r8d, 255
    ja .parse_ip_invalid
    cmp r9d, 3
    jne .parse_ip_invalid
    mov ebx, r8d
    mov ecx, r9d
    shl ecx, 3
    shl ebx, cl
    or eax, ebx
    pop rbx
    ret

.parse_ip_invalid:
    xor eax, eax
    pop rbx
    ret

; parse_port
; rdi -> null-terminated port string
; returns ax = host-order port, or 0 on error
parse_port:
    push rbx
    xor eax, eax

.parse_port_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_port_done
    sub bl, '0'
    cmp bl, 9
    ja .parse_port_invalid
    imul eax, eax, 10
    add eax, ebx
    cmp eax, 65535
    ja .parse_port_invalid
    inc rdi
    jmp .parse_port_loop

.parse_port_done:
    pop rbx
    ret

.parse_port_invalid:
    xor eax, eax
    pop rbx
    ret

; parse_port_range
; rdi -> null-terminated string: "N" or "N-M"
; returns ax = start port, dx = end port; ax=0 on error
parse_port_range:
    push rbx
    xor eax, eax
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    xor ecx, ecx

.parse_range_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_range_done
    cmp bl, '-'
    je .parse_range_dash
    sub bl, '0'
    cmp bl, 9
    ja .parse_range_invalid
    cmp ecx, 0
    jne .parse_range_add_end
    imul eax, eax, 10
    add eax, ebx
    inc r8d
    cmp eax, 65535
    ja .parse_range_invalid
    jmp .parse_range_next

.parse_range_add_end:
    imul edx, edx, 10
    add edx, ebx
    inc r9d
    cmp edx, 65535
    ja .parse_range_invalid
    jmp .parse_range_next

.parse_range_dash:
    cmp ecx, 0
    jne .parse_range_invalid
    mov ecx, 1
    jmp .parse_range_next

.parse_range_next:
    inc rdi
    jmp .parse_range_loop

.parse_range_done:
    cmp r8d, 0
    je .parse_range_invalid
    cmp ecx, 0
    je .parse_range_single
    cmp r9d, 0
    je .parse_range_invalid
    test eax, eax
    jz .parse_range_invalid
    test edx, edx
    jz .parse_range_invalid
    cmp edx, eax
    jb .parse_range_invalid
    pop rbx
    ret

.parse_range_single:
    test eax, eax
    jz .parse_range_invalid
    mov edx, eax
    pop rbx
    ret

.parse_range_invalid:
    xor eax, eax
    xor edx, edx
    pop rbx
    ret

; parse_u32
; rdi -> null-terminated decimal string
; returns eax = value, or 0 on error
parse_u32:
    push rbx
    xor eax, eax

.parse_u32_loop:
    movzx ebx, byte [rdi]
    cmp bl, 0
    je .parse_u32_done
    sub bl, '0'
    cmp bl, 9
    ja .parse_u32_invalid
    imul eax, eax, 10
    add eax, ebx
    inc rdi
    jmp .parse_u32_loop

.parse_u32_done:
    test eax, eax
    jz .parse_u32_invalid
    pop rbx
    ret

.parse_u32_invalid:
    xor eax, eax
    pop rbx
    ret

; parse_scan_mode
; rdi -> null-terminated mode string
; returns al = scan mode, or 0 on error
parse_scan_mode:
    push rbx
    mov al, [rdi]
    cmp al, 's'
    jne .scan_ack
    cmp byte [rdi+1], 'y'
    jne .scan_ack
    cmp byte [rdi+2], 'n'
    jne .scan_ack
    cmp byte [rdi+3], 0
    jne .scan_ack
    mov al, SCAN_SYN
    pop rbx
    ret

.scan_ack:
    cmp al, 'a'
    jne .scan_fin
    cmp byte [rdi+1], 'c'
    jne .scan_fin
    cmp byte [rdi+2], 'k'
    jne .scan_fin
    cmp byte [rdi+3], 0
    jne .scan_fin
    mov al, SCAN_ACK
    pop rbx
    ret

.scan_fin:
    cmp al, 'f'
    jne .scan_null
    cmp byte [rdi+1], 'i'
    jne .scan_null
    cmp byte [rdi+2], 'n'
    jne .scan_null
    cmp byte [rdi+3], 0
    jne .scan_null
    mov al, SCAN_FIN
    pop rbx
    ret

.scan_null:
    cmp al, 'n'
    jne .scan_xmas
    cmp byte [rdi+1], 'u'
    jne .scan_xmas
    cmp byte [rdi+2], 'l'
    jne .scan_xmas
    cmp byte [rdi+3], 'l'
    jne .scan_xmas
    cmp byte [rdi+4], 0
    jne .scan_xmas
    mov al, SCAN_NULL
    pop rbx
    ret

.scan_xmas:
    cmp al, 'x'
    jne .scan_window
    cmp byte [rdi+1], 'm'
    jne .scan_window
    cmp byte [rdi+2], 'a'
    jne .scan_window
    cmp byte [rdi+3], 's'
    jne .scan_window
    cmp byte [rdi+4], 0
    jne .scan_window
    mov al, SCAN_XMAS
    pop rbx
    ret

.scan_window:
    cmp al, 'w'
    jne .scan_maimon
    cmp byte [rdi+1], 'i'
    jne .scan_maimon
    cmp byte [rdi+2], 'n'
    jne .scan_maimon
    cmp byte [rdi+3], 'd'
    jne .scan_maimon
    cmp byte [rdi+4], 'o'
    jne .scan_maimon
    cmp byte [rdi+5], 'w'
    jne .scan_maimon
    cmp byte [rdi+6], 0
    jne .scan_maimon
    mov al, SCAN_WINDOW
    pop rbx
    ret

.scan_maimon:
    cmp al, 'm'
    jne .scan_invalid
    cmp byte [rdi+1], 'a'
    jne .scan_invalid
    cmp byte [rdi+2], 'i'
    jne .scan_invalid
    cmp byte [rdi+3], 'm'
    jne .scan_invalid
    cmp byte [rdi+4], 'o'
    jne .scan_invalid
    cmp byte [rdi+5], 'n'
    jne .scan_invalid
    cmp byte [rdi+6], 0
    jne .scan_invalid
    mov al, SCAN_MAIMON
    pop rbx
    ret

.scan_invalid:
    xor eax, eax
    pop rbx
    ret
