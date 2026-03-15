%ifndef DEMUX_INC
%define DEMUX_INC 1

recv_and_classify:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    js .no_response

    lea rsi, [recv_buf]
    cmp byte [rsi+9], 6
    jne .no_response

    mov eax, [rsi+12]
    cmp byte [cidr_mode], 0
    jne .src_ok
    cmp eax, [target_ip]
    jne .no_response
.src_ok:

    movzx eax, byte [rsi]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [rsi+rdi]

    movzx ecx, word [rdx]
    xchg cl, ch

    mov  edx, [rdx+8]
    bswap edx
    mov  edi, [rsi+12]
    call cookie_verify
    jne  .no_response

    mov al, [rsi+8]
    mov [last_ttl], al
    mov ax, [rdx+14]
    xchg al, ah
    mov [last_win], ax

    push rcx
    call inflight_remove
    pop rcx

    call intel_rtt_record

    cmp byte [os_enabled], 0
    je .classify_now
    call intel_analyze

.classify_now:
    mov al, [rdx+13]
    mov bl, al
    mov dl, [scan_mode]
    cmp dl, SCAN_SYN
    je .check_syn
    cmp dl, SCAN_ACK
    je .check_ack
    cmp dl, SCAN_WINDOW
    je .check_ack
    test bl, 0x04
    jnz .is_closed
    jmp .is_filtered

.check_ack:
    test bl, 0x04
    jnz .is_open
    jmp .is_filtered

.check_syn:
    and bl, 0x12
    cmp bl, 0x12
    je .is_open
    test al, 0x04
    jnz .is_closed
    jmp .is_filtered

.is_open:
    call record_open
    mov ax, cx
    call write_open_intel
    cmp byte [os_enabled], 0
    je .classified
    mov word [intel_port_cur], cx
    call intel_print_record
    jmp .classified

.is_closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    jmp .classified

.is_filtered:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result

.classified:
    mov eax, 1
    ; Secondary callback check
    cmp  byte [cb_secondary_enabled], 0
    je   .no_cb_secondary
    lea  rsi, [recv_buf]
    call cb_secondary_check
.no_cb_secondary:
    jmp .done

.no_response:
    xor eax, eax

.done:
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

%endif
