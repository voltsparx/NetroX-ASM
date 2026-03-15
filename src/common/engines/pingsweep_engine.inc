; ============================================================
; pingsweep_engine.inc - scan engine (stub)
; ============================================================

%ifndef PINGSWEEP_ENGINE_INC
%define PINGSWEEP_ENGINE_INC 1

; ------------------------------------------------------------
; pingsweep_run
; ICMP echo + TCP SYN/ACK probes per host
; ------------------------------------------------------------
pingsweep_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; init counters
    mov dword [sweep_up_count], 0
    mov dword [sweep_down_count], 0

    ; if no CIDR, just scan target_ip
    cmp byte [cidr_mode], 1
    jne .single_target

    xor r12d, r12d  ; range index
    xor r13d, r13d  ; offset in ranges
.range_loop:
    cmp r12d, [ip_range_count]
    jae .done
    lea rsi, [ip_ranges + r12*8]
    mov r14d, [rsi]     ; start_ip
    mov r15d, [rsi+4]   ; count
    xor ebx, ebx
.host_loop:
    cmp ebx, r15d
    jae .next_range
    mov eax, r14d
    add eax, ebx
    mov [current_scan_ip], eax
    call pingsweep_probe_ip
    inc ebx
    jmp .host_loop
.next_range:
    inc r12d
    jmp .range_loop

.single_target:
    mov eax, [target_ip]
    mov [current_scan_ip], eax
    call pingsweep_probe_ip
    jmp .done

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ------------------------------------------------------------
; pingsweep_probe_ip
; Uses current_scan_ip
; ------------------------------------------------------------
pingsweep_probe_ip:
    push rbx
    push rcx
    push rdx

    ; ICMP echo probe
    mov eax, [current_scan_ip]
    mov [target_ip], eax
    mov byte [engine_id], ENGINE_ICMP
    mov word [dst_port_be], 0
    call build_icmp_packet
    call intel_rtt_start
    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 60
    xor r10d, r10d
    lea r8, [sockaddr_dst]
    mov r9d, 16
    syscall

    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 500
    syscall
    test rax, rax
    jle .try_syn

    ; recv any ICMP reply
    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .try_syn
    ; mark UP via ICMP
    mov byte [sweep_method], 1
    call pingsweep_print_up
    jmp .probe_done

.try_syn:
    ; TCP SYN to 443
    mov word [dst_port_be], 0xBB01 ; 443
    mov byte [engine_id], ENGINE_SYN
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

    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov edx, 1
    mov r10d, 500
    syscall
    test rax, rax
    jle .try_ack

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .try_ack
    mov byte [sweep_method], 2
    call pingsweep_print_up
    jmp .probe_done

.try_ack:
    ; TCP ACK to 80
    mov word [dst_port_be], 0x5000 ; 80
    mov byte [scan_mode], SCAN_ACK
    call build_syn_packet
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
    mov r10d, 500
    syscall
    test rax, rax
    jle .mark_down

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .mark_down
    mov byte [sweep_method], 3
    call pingsweep_print_up
    jmp .probe_done

.mark_down:
    inc dword [sweep_down_count]
    ; print down line (IP only)
    mov eax, [current_scan_ip]
    call ip_print_addr
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [filtered_msg]
    mov edx, filtered_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    jmp .probe_done

.probe_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; ------------------------------------------------------------
; pingsweep_print_up
; ------------------------------------------------------------
pingsweep_print_up:
    inc dword [sweep_up_count]
    mov eax, [current_scan_ip]
    call ip_print_addr
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [open_msg]
    mov edx, open_msg_len
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    ret

%endif
