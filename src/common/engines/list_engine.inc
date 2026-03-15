; ============================================================
; list_engine.inc - scan engine (stub)
; ============================================================

%ifndef LIST_ENGINE_INC
%define LIST_ENGINE_INC 1

SECTION .rodata
list_nohost_msg db " (no hostname)", 0

SECTION .text

; ------------------------------------------------------------
; list_run
; Prints targets without sending any packets
; ------------------------------------------------------------
list_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    cmp byte [cidr_mode], 1
    jne .single_target

    xor r12d, r12d
.range_loop:
    cmp r12d, [ip_range_count]
    jae .done
    lea rsi, [ip_ranges + r12*8]
    mov r14d, [rsi]
    mov r15d, [rsi+4]
    xor ebx, ebx
.host_loop:
    cmp ebx, r15d
    jae .next_range
    mov eax, r14d
    add eax, ebx
    mov [current_scan_ip], eax
    call list_print_ip
    inc ebx
    jmp .host_loop
.next_range:
    inc r12d
    jmp .range_loop

.single_target:
    mov eax, [target_ip]
    mov [current_scan_ip], eax
    call list_print_ip

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

list_print_ip:
    mov eax, [current_scan_ip]
    call ip_print_addr
    lea rsi, [list_nohost_msg]
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .len_done
    inc edx
    jmp .len
.len_done:
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

%endif
