; ============================================================
; script_engine.inc - scan engine (stub)
; ============================================================

%ifndef SCRIPT_ENGINE_INC
%define SCRIPT_ENGINE_INC 1

; ------------------------------------------------------------
; script_run
; Run baseline scan then script probes
; ------------------------------------------------------------
script_run:
    mov byte [script_mode], 1
    jmp scan_loop_entry

; ------------------------------------------------------------
; script_post_scan
; Run probes on all open ports in result_map
; ------------------------------------------------------------
script_post_scan:
    push rbx
    push r12
    push r13

    xor r12d, r12d          ; port index (0..65534)
.port_loop:
    cmp r12d, 65535
    jae .done
    mov eax, r12d
    mov edx, eax
    shr eax, 3
    and edx, 7
    mov bl, [result_map+rax]
    mov cl, 1
    shl cl, dl
    test bl, cl
    jz .next

    mov ecx, r12d
    inc ecx
    call script_probe_port

.next:
    inc r12d
    jmp .port_loop

.done:
    pop r13
    pop r12
    pop rbx
    ret

; ------------------------------------------------------------
; script_probe_port
; ecx = port
; ------------------------------------------------------------
script_probe_port:
    push rbx
    push r12
    push r13
    push r14

    ; open TCP socket
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    xor rdx, rdx
    syscall
    test rax, rax
    js .done
    mov [connect_fd], rax

    ; set port
    mov ax, cx
    xchg al, ah
    mov [sockaddr_dst+2], ax

    ; connect
    mov rax, SYS_CONNECT
    mov rdi, [connect_fd]
    lea rsi, [sockaddr_dst]
    mov rdx, 16
    syscall
    test rax, rax
    js .close

    ; send probe based on port
    lea rsi, [script_result_buf]
    mov r13d, 0
    cmp ecx, 80
    je .send_http
    cmp ecx, 8080
    je .send_http
    cmp ecx, 8443
    je .send_http
    cmp ecx, 25
    je .send_smtp
    cmp ecx, 587
    je .send_smtp
    cmp ecx, 21
    je .send_ftp
    jmp .recv_only

.send_http:
    lea rsi, [http_probe]
    mov edx, http_probe_len
    jmp .send_buf
.send_smtp:
    lea rsi, [smtp_probe]
    mov edx, smtp_probe_len
    jmp .send_buf
.send_ftp:
    lea rsi, [ftp_probe]
    mov edx, ftp_probe_len
    jmp .send_buf

.send_buf:
    mov rax, SYS_WRITE
    mov rdi, [connect_fd]
    syscall
    jmp .recv_only

.recv_only:
    ; read banner (up to 512)
    mov rax, SYS_READ
    mov rdi, [connect_fd]
    lea rsi, [recv_buf]
    mov edx, 512
    syscall
    test rax, rax
    jle .close
    mov r12d, eax
    mov word [intel_banner_len], ax
    lea rdi, [intel_banner]
    lea rsi, [recv_buf]
    mov ecx, eax
    rep movsb
    call intel_banner_match

    ; print: port + service + banner
    mov ax, cx
    call append_u16
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [intel_svc_name]
    mov edx, 16
    call buf_write
    lea rsi, [space_msg]
    mov edx, space_len
    call buf_write
    lea rsi, [intel_banner]
    movzx edx, word [intel_banner_len]
    call buf_write
    lea rsi, [newline_msg]
    mov edx, newline_len
    call buf_write

.close:
    mov rax, SYS_CLOSE
    mov rdi, [connect_fd]
    syscall
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

SECTION .rodata
http_probe db "HEAD / HTTP/1.0", 13, 10, 13, 10
http_probe_len equ $-http_probe
smtp_probe db "EHLO netrox", 13, 10
smtp_probe_len equ $-smtp_probe
ftp_probe db "FEAT", 13, 10
ftp_probe_len equ $-ftp_probe

%endif
