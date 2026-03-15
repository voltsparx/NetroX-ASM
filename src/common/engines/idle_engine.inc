; ============================================================
; idle_engine.inc - scan engine (stub)
; ============================================================

%ifndef IDLE_ENGINE_INC
%define IDLE_ENGINE_INC 1

SECTION .text

; ------------------------------------------------------------
; idle_run
; Idle/Zombie scan
; ------------------------------------------------------------
idle_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    cmp dword [zombie_ip], 0
    jne .z_ok
    ret
.z_ok:
    cmp word [zombie_port], 0
    jne .zp_ok
    mov word [zombie_port], 80
.zp_ok:
    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov r14d, r15d
    sub r14d, ecx
    inc r14d
    xor ebx, ebx

.idle_loop:
    cmp ebx, r14d
    jae .idle_done

    ; permute port
    mov rdi, rbx
    mov rsi, r14
    call blackrock_permute
    movzx ecx, word [start_port]
    add ecx, eax

    ; baseline IPID from zombie
    call idle_probe_zombie
    mov [idle_ipid_before], ax

    ; spoofed SYN to target from zombie
    push rcx
    call idle_send_spoofed_syn
    pop rcx

    ; measure IPID after
    call idle_probe_zombie
    mov [idle_ipid_after], ax

    ; delta
    mov ax, [idle_ipid_after]
    sub ax, [idle_ipid_before]
    mov [idle_ipid_delta], ax

    ; classify
    cmp ax, 2
    je .idle_open
    cmp ax, 1
    je .idle_closed
    ; noisy
    jmp .idle_filtered

.idle_open:
    mov ax, cx
    call record_open
    mov ax, cx
    call write_open_intel
    jmp .idle_next

.idle_closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    inc dword [closed_count]
    jmp .idle_next

.idle_filtered:
    mov ax, cx
    mov r9, filtered_msg
    mov r10d, filtered_len
    call write_result
    inc dword [filtered_count]

.idle_next:
    inc ebx
    jmp .idle_loop

.idle_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ------------------------------------------------------------
; idle_probe_zombie
; Sends SYN/ACK to zombie, reads RST, returns IPID in AX
; ------------------------------------------------------------
idle_probe_zombie:
    push rbx
    push rcx

    ; target zombie
    mov eax, [zombie_ip]
    mov [target_ip], eax
    mov ax, [zombie_port]
    xchg al, ah
    mov [dst_port_be], ax

    ; build SYN then override flags to SYN/ACK
    mov byte [scan_mode], SCAN_SYN
    call build_syn_packet
    mov byte [packet_buf+33], 0x12
    mov word [packet_buf+36], 0
    lea rdi, [packet_buf]
    call tcp_checksum
    mov [packet_buf+36], ax

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 40
    xor r10d, r10d
    lea r8, [sockaddr_dst]
    mov r9d, 16
    syscall

    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 1000
    syscall
    test rax, rax
    jle .no_ipid

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .no_ipid

    ; verify src ip = zombie
    mov eax, [recv_buf+12]
    cmp eax, [zombie_ip]
    jne .no_ipid

    ; read IP ID
    movzx eax, word [recv_buf+4]
    xchg al, ah
    mov ax, ax
    jmp .done

.no_ipid:
    xor ax, ax
.done:
    pop rcx
    pop rbx
    ret

; ------------------------------------------------------------
; idle_send_spoofed_syn
; ecx = target port
; ------------------------------------------------------------
idle_send_spoofed_syn:
    push rax
    push rbx
    push rcx

    ; preserve source_ip
    mov eax, [source_ip]
    push rax

    ; set spoofed source to zombie
    mov eax, [zombie_ip]
    mov [source_ip], eax

    ; restore target_ip from current_scan_ip if set
    mov eax, [current_scan_ip]
    test eax, eax
    jz .use_target
    mov [target_ip], eax
.use_target:
    mov ax, cx
    xchg al, ah
    mov [dst_port_be], ax
    mov [sockaddr_dst+2], ax

    mov byte [scan_mode], SCAN_SYN
    call build_syn_packet

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 40
    xor r10d, r10d
    lea r8, [sockaddr_dst]
    mov r9d, 16
    syscall

    ; restore source_ip
    pop rax
    mov [source_ip], eax

    pop rcx
    pop rbx
    pop rax
    ret

%endif
