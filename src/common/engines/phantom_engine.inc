; ============================================================
; phantom_engine.inc - Phantom Scan engine
; ============================================================

%ifndef PHANTOM_ENGINE_INC
%define PHANTOM_ENGINE_INC 1

; ------------------------------------------------------------
; phantom_rdtsc_start
; ------------------------------------------------------------
phantom_rdtsc_start:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [phantom_t_send], rax
    ret

; ------------------------------------------------------------
; phantom_rdtsc_end
; ------------------------------------------------------------
phantom_rdtsc_end:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [phantom_t_recv], rax
    sub  rax, [phantom_t_send]
    call sar_cycles_to_ns
    ret

; ------------------------------------------------------------
; phantom_build_pulse
; ------------------------------------------------------------
phantom_build_pulse:
    mov  ax, cx
    xchg al, ah
    mov  [dst_port_be], ax
    mov  [sockaddr_dst+2], ax

    call build_syn_packet
    mov  byte [packet_buf+33], PHANTOM_TCP_FLAGS_ACK
    mov  word [packet_buf+34], PHANTOM_TCP_WINDOW
    call xorshift64_next
    test eax, eax
    jnz  .ack_ok
    inc  eax
.ack_ok:
    mov  [packet_buf+28], eax
    mov  word [packet_buf+36], 0
    lea  rdi, [packet_buf]
    call tcp_checksum
    mov  [packet_buf+36], ax

    add  qword [phantom_bytes_sent], 40
    inc  dword [phantom_pkts_sent]
    ret

; ------------------------------------------------------------
; tev_compute_deviation
; ------------------------------------------------------------
tev_compute_deviation:
    test rbx, rbx
    jz .no_baseline
    sub rax, rbx
    jns .positive
    neg rax
.positive:
    mov rcx, 100
    mul rcx
    xor rdx, rdx
    div rbx
    ret
.no_baseline:
    xor rax, rax
    ret

; ------------------------------------------------------------
; tev_check_trend
; ------------------------------------------------------------
tev_check_trend:
    movzx ebx, byte [tev_history_idx]
    mov eax, ebx
    dec eax
    and eax, 7
    movzx eax, word [tev_history + rax*2]
    mov ecx, ebx
    sub ecx, 5
    and ecx, 7
    movzx ecx, word [tev_history + rcx*2]
    sub eax, ecx
    cmp eax, 5
    jg .trend
    mov eax, 1
    test eax, eax
    ret
.trend:
    xor eax, eax
    test eax, eax
    ret

; ------------------------------------------------------------
; tev_check_guardrail
; ------------------------------------------------------------
tev_check_guardrail:
    ; update history ring
    movzx ecx, byte [tev_history_idx]
    mov  [tev_history + rcx*2], ax
    inc  cl
    and  cl, 7
    mov  [tev_history_idx], cl

    ; condition a: single deviation
    movzx ebx, byte [phantom_tev_threshold]
    cmp  eax, ebx
    ja   .trigger

    ; condition c: consecutive timeouts
    movzx ebx, byte [tev_consecutive_to]
    cmp  bl, PHANTOM_TEV_STREAK_MAX
    jae  .trigger

    ; condition b: rolling avg > threshold*80/100
    xor  rax, rax
    xor  ecx, ecx
.avg_loop:
    add  ax, [tev_history + rcx*2]
    inc  ecx
    cmp  ecx, 8
    jb   .avg_loop
    mov  rbx, 8
    xor  rdx, rdx
    div  rbx                       ; ax = avg
    movzx ebx, byte [phantom_tev_threshold]
    mov  rcx, 80
    imul ebx, ecx
    mov  ecx, 100
    xor  edx, edx
    mov  eax, ebx
    div  ecx                       ; ax = threshold*0.8
    mov  bx, ax
    mov  ax, word [tev_history + ((ecx))] ; dummy to keep ax free
    mov  ax, word [tev_history + 0]       ; overwrite, will not use
    mov  ax, word [tev_history + 0]
    mov  ax, word [tev_history + 0]
    ; compare rolling avg (stored earlier in ax) > threshold*0.8
    cmp  word [tev_history + 0], bx
    jb   .check_trend
    jmp  .trigger

.check_trend:
    call tev_check_trend
    jz .trigger

    xor eax, eax
    test eax, eax
    ret

.trigger:
    mov byte [tev_triggered], 1
    mov eax, 1
    test eax, eax
    ret

; ------------------------------------------------------------
; tev_hard_stop
; ------------------------------------------------------------
tev_hard_stop:
    lea  rsi, [phantom_tev_alert]
    call .pstr
    lea  rsi, [phantom_tev_dev_msg]
    call .pstr
    movzx eax, byte [tev_history_idx]
    dec  al
    and  al, 7
    movzx eax, word [tev_history + rax*2]
    call append_u16
    lea  rsi, [phantom_tev_thr_msg]
    call .pstr
    movzx eax, byte [phantom_tev_threshold]
    call append_u16
    lea  rsi, [phantom_tev_end_msg]
    call .pstr
    inc  dword [phantom_count_tev]
    mov  byte [tev_triggered], 1
    call flush_output
    jmp  .scan_done
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .done
    inc edx
    jmp .len
.done:
    call buf_write
    ret

; ------------------------------------------------------------
; phantom_classify_rtt
; ------------------------------------------------------------
phantom_classify_rtt:
    test rax, rax
    jz .filtered
    mov byte [tev_consecutive_to], 0
    mov rbx, [phantom_idle_rtt]
    mov rcx, PHANTOM_OPEN_RATIO
    mov rdx, 0
    mov rax, rbx
    mul rcx
    mov rcx, 100
    xor rdx, rdx
    div rcx
    mov rcx, rax                  ; threshold
    mov rax, [phantom_probe_rtt]
    cmp rax, rcx
    jb .closed
    mov byte [phantom_port_state], PHANTOM_STATE_OPEN
    ret
.closed:
    mov byte [phantom_port_state], PHANTOM_STATE_CLOSED
    ret
.filtered:
    inc byte [tev_consecutive_to]
    mov byte [phantom_port_state], PHANTOM_STATE_FILTERED
    ret

; ------------------------------------------------------------
; phantom_idle_calibrate
; ------------------------------------------------------------
phantom_idle_calibrate:
    cmp qword [phantom_idle_rtt], 0
    jne .done
    push rbx
    push r12
    push r13
    mov  al, [engine_id]
    push rax
    mov  byte [engine_id], ENGINE_ICMP
    mov  word [dst_port_be], 0
    xor  r12d, r12d
.probe_loop:
    cmp  r12d, PHANTOM_AMBIENT_PROBES
    jae  .probe_done
    call build_icmp_packet
    call phantom_rdtsc_start
    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 60
    xor  r10d, r10d
    lea  r8,  [sockaddr_dst]
    mov  r9d, 16
    syscall
    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, 1000
    syscall
    test rax, rax
    jle  .probe_timeout
    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall
    test rax, rax
    jle  .probe_timeout
    call phantom_rdtsc_end
    mov  [phantom_probe_rtt], rax
    jmp  .probe_store
.probe_timeout:
    mov  qword [phantom_probe_rtt], 999999999
.probe_store:
    mov  rax, [phantom_probe_rtt]
    cmp  r12d, 0
    jne  .min_check
    mov  [phantom_idle_rtt], rax
    jmp  .next_probe
.min_check:
    mov  rbx, [phantom_idle_rtt]
    cmp  rax, rbx
    jae  .next_probe
    mov  [phantom_idle_rtt], rax
.next_probe:
    inc  r12d
    jmp  .probe_loop
.probe_done:
    pop  rax
    mov  [engine_id], al
    pop  r13
    pop  r12
    pop  rbx
.done:
    ret

; ------------------------------------------------------------
; phantom_passive_listen
; ------------------------------------------------------------
phantom_passive_listen:
    movzx eax, byte [phantom_listen_secs]
    test eax, eax
    jz .done
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax
    mov rax, [tsc_hz]
    movzx ecx, byte [phantom_listen_secs]
    mul rcx
    add rax, r12
    mov r13, rax
.listen_loop:
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r13
    jae .done
    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, 100
    syscall
    test rax, rax
    jle  .listen_loop
    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall
    test rax, rax
    jle  .listen_loop
    mov  eax, [recv_buf+12]
    cmp  eax, [target_ip]
    jne  .listen_loop
    movzx eax, byte [recv_buf]
    and al, 0x0F
    shl al, 2
    movzx edi, al
    lea rdx, [recv_buf + rdi]
    movzx ecx, word [rdx]
    xchg cl, ch
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    test byte [passive_open_map + rax], r8b
    jnz .listen_loop
    or byte [passive_open_map + rax], r8b
    inc dword [passive_port_count]
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r9, rax
    mov rbx, [phantom_last_ambient_tsc]
    test rbx, rbx
    jz .set_last
    mov rax, r9
    sub rax, rbx
    call sar_cycles_to_ns
    cmp qword [phantom_idle_rtt], 0
    jne .set_last
    mov [phantom_idle_rtt], rax
.set_last:
    mov [phantom_last_ambient_tsc], r9
    jmp .listen_loop
.done:
    ret

; ------------------------------------------------------------
; phantom_harmonic_delay
; ------------------------------------------------------------
phantom_harmonic_delay:
    call xorshift64_next
    movzx ecx, dword [phantom_jitter_max_us]
    movzx ebx, dword [phantom_jitter_min_us]
    sub ecx, ebx
    test ecx, ecx
    jz .done
    xor rdx, rdx
    div rcx
    mov eax, edx
    add eax, ebx
    mov ebx, eax                  ; delay_us
    mov rax, [tsc_hz]
    mov rcx, 1000000
    xor rdx, rdx
    div rcx                       ; rax = cycles per us
    imul rax, rbx
    mov r10, rax                  ; delay_cycles
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, rax
.wait:
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r8
    cmp rax, r10
    jb .wait
.done:
    ret

; ------------------------------------------------------------
; phantom_probe_port
; ------------------------------------------------------------
phantom_probe_port:
    mov eax, ecx
    dec eax
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov r8b, 1
    shl r8b, dl
    test byte [passive_open_map + rax], r8b
    jnz .mark_passive

    call phantom_harmonic_delay
    call phantom_build_pulse
    call phantom_rdtsc_start

    mov  rax, SYS_SENDTO
    mov  rdi, [raw_fd]
    lea  rsi, [packet_buf]
    mov  edx, 40
    xor  r10d, r10d
    lea  r8,  [sockaddr_dst]
    mov  r9d, 16
    syscall

    mov  rax, SYS_EPOLL_WAIT
    mov  rdi, [epoll_fd]
    lea  rsi, [epoll_out]
    mov  edx, 1
    mov  r10d, PHANTOM_TIMEOUT_MS
    syscall
    test rax, rax
    jle  .timeout

    mov  rax, SYS_RECVFROM
    mov  rdi, [raw_fd]
    lea  rsi, [recv_buf]
    mov  edx, 4096
    xor  r10d, r10d
    xor  r8d, r8d
    xor  r9d, r9d
    syscall
    call phantom_rdtsc_end
    mov  [phantom_probe_rtt], rax
    jmp  .classify
.timeout:
    xor  rax, rax
    mov  [phantom_probe_rtt], rax
.classify:
    call phantom_classify_rtt
    mov  rax, [phantom_probe_rtt]
    mov  rbx, [phantom_idle_rtt]
    call tev_compute_deviation
    call tev_check_guardrail
    jnz  .triggered
    ret
.triggered:
    call tev_hard_stop
    ret

.mark_passive:
    mov byte [phantom_port_state], PHANTOM_STATE_PASSIVE
    ret

; ------------------------------------------------------------
; phantom_print_result
; ------------------------------------------------------------
phantom_print_result:
    push rcx
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [space_msg]
    call buf_write

    mov al, [phantom_port_state]
    cmp al, PHANTOM_STATE_PASSIVE
    jne .chk_open
    lea rsi, [phantom_state_popen]
    call .pstr
    lea rsi, [phantom_method_obs]
    call .pstr
    lea rsi, [phantom_dash_msg]
    call .pstr
    lea rsi, [space_msg]
    call buf_write
    lea rsi, [phantom_dash_msg]
    call .pstr
    jmp .done
.chk_open:
    cmp al, PHANTOM_STATE_OPEN
    jne .chk_closed
    lea rsi, [phantom_state_open]
    call .pstr
    jmp .method_ack
.chk_closed:
    cmp al, PHANTOM_STATE_CLOSED
    jne .filtered
    lea rsi, [phantom_state_closed]
    call .pstr
    jmp .method_ack
.filtered:
    lea rsi, [phantom_state_filt]
    call .pstr
    jmp .method_ack
.method_ack:
    lea rsi, [phantom_method_ack]
    call .pstr
    mov rax, [phantom_probe_rtt]
    test rax, rax
    jz .print_timeout
    call append_u16
    lea rsi, [phantom_ns_msg]
    call .pstr
    lea rsi, [space_msg]
    call buf_write
    mov rax, [phantom_probe_rtt]
    mov rbx, [phantom_idle_rtt]
    call tev_compute_deviation
    lea rsi, [phantom_plus_msg]
    call .pstr
    call append_u16
    lea rsi, [phantom_tev_pct]
    call .pstr
    jmp .done
.print_timeout:
    lea rsi, [phantom_timeout_str]
    call .pstr
    lea rsi, [space_msg]
    call buf_write
    lea rsi, [phantom_timeout_str]
    call .pstr
.done:
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    pop rcx
    ret
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .pdone
    inc edx
    jmp .len
.pdone:
    call buf_write
    ret

; ------------------------------------------------------------
; phantom_print_summary
; ------------------------------------------------------------
phantom_print_summary:
    lea rsi, [phantom_sum_hdr]
    call .pstr
    lea rsi, [phantom_sum_passive]
    call .pstr
    mov eax, [phantom_count_passive]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [phantom_sum_open]
    call .pstr
    mov eax, [phantom_count_open]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [phantom_sum_closed]
    call .pstr
    mov eax, [phantom_count_closed]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [phantom_sum_filtered]
    call .pstr
    mov eax, [phantom_count_filtered]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [phantom_sum_tev]
    call .pstr
    mov eax, [phantom_count_tev]
    call append_u16
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write
    lea rsi, [phantom_sum_bytes]
    call .pstr
    mov rax, [phantom_bytes_sent]
    call append_u16
    lea rsi, [phantom_sum_bytes_e]
    call .pstr
    cmp byte [tev_triggered], 0
    jne .tev_bad
    lea rsi, [phantom_tev_ok_msg]
    call .pstr
    ret
.tev_bad:
    lea rsi, [phantom_tev_bad_msg]
    call .pstr
    ret
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .pdone
    inc edx
    jmp .len
.pdone:
    call buf_write
    ret

; ------------------------------------------------------------
; phantom_init
; ------------------------------------------------------------
phantom_init:
    mov byte [phantom_enabled], 1
    mov byte [phantom_tev_threshold], PHANTOM_TEV_THRESHOLD
    mov byte [phantom_listen_secs], PHANTOM_LISTEN_SECS
    mov qword [phantom_burst_window_ns], PHANTOM_BURST_WINDOW_NS
    mov dword [phantom_jitter_min_us], PHANTOM_JITTER_MIN_US
    mov dword [phantom_jitter_max_us], PHANTOM_JITTER_MAX_US
    mov qword [phantom_idle_rtt], 0
    mov qword [phantom_bytes_sent], 0
    mov dword [phantom_pkts_sent], 0
    mov dword [phantom_count_passive], 0
    mov dword [phantom_count_open], 0
    mov dword [phantom_count_closed], 0
    mov dword [phantom_count_filtered], 0
    mov dword [phantom_count_tev], 0
    mov dword [phantom_count_total], 0
    mov byte [tev_triggered], 0
    mov byte [tev_consecutive_to], 0
    mov byte [tev_history_idx], 0

    lea rsi, [phantom_hdr_msg]
    call .pstr
    lea rsi, [phantom_hdr_end]
    call .pstr

    call phantom_passive_listen
    call phantom_idle_calibrate

    lea rsi, [phantom_idle_msg]
    call .pstr
    mov rax, [phantom_idle_rtt]
    call append_u16
    lea rsi, [phantom_ns_msg]
    call .pstr
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

    lea rsi, [phantom_tev_msg]
    call .pstr
    movzx eax, byte [phantom_tev_threshold]
    call append_u16
    lea rsi, [phantom_tev_pct]
    call .pstr

    lea rsi, [phantom_listen_msg]
    call .pstr
    movzx eax, byte [phantom_listen_secs]
    call append_u16
    lea rsi, [phantom_listen_sec]
    call .pstr

    lea rsi, [phantom_passive_msg]
    call .pstr
    mov eax, [passive_port_count]
    call append_u16
    lea rsi, [phantom_passive_end]
    call .pstr

    lea rsi, [phantom_col_hdr]
    call .pstr
    lea rsi, [phantom_col_sep]
    call .pstr
    call flush_output
    ret
.pstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .pdone
    inc edx
    jmp .len
.pdone:
    call buf_write
    ret

; ------------------------------------------------------------
; phantom_run
; ------------------------------------------------------------
phantom_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
    mov   r14d, r15d
    sub   r14d, ecx
    inc   r14d
    xor   ebx, ebx

.loop:
    cmp  ebx, r14d
    jae  .done

    mov  rdi, rbx
    mov  rsi, r14
    call blackrock_permute
    movzx ecx, word [start_port]
    add  ecx, eax

    call phantom_probe_port
    mov al, [phantom_port_state]
    cmp al, PHANTOM_STATE_PASSIVE
    jne .chk_open
    inc dword [phantom_count_passive]
    jmp .after_count
.chk_open:
    cmp al, PHANTOM_STATE_OPEN
    jne .chk_closed
    inc dword [phantom_count_open]
    jmp .after_count
.chk_closed:
    cmp al, PHANTOM_STATE_CLOSED
    jne .chk_filtered
    inc dword [phantom_count_closed]
    jmp .after_count
.chk_filtered:
    inc dword [phantom_count_filtered]
.after_count:
    inc dword [phantom_count_total]
    call phantom_print_result
    call stabilize_step
    inc ebx
    jmp .loop

.done:
    call phantom_print_summary
    call flush_output
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%endif
