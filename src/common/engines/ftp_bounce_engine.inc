; ============================================================
; ftp_bounce_engine.inc - scan engine (stub)
; ============================================================

%ifndef FTP_BOUNCE_ENGINE_INC
%define FTP_BOUNCE_ENGINE_INC 1

SECTION .rodata
ftp_user_cmd db "USER anonymous", 13, 10, 0
ftp_pass_cmd db "PASS guest", 13, 10, 0
ftp_type_cmd db "TYPE I", 13, 10, 0
ftp_list_cmd db "LIST", 13, 10, 0

SECTION .text

; ------------------------------------------------------------
; ftp_bounce_run
; ------------------------------------------------------------
ftp_bounce_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; require proxy
    cmp dword [ftp_proxy_ip], 0
    jne .proxy_ok
    jmp .done
.proxy_ok:
    ; connect to FTP proxy
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    xor rdx, rdx
    syscall
    test rax, rax
    js .done
    mov [ftp_ctrl_fd], rax

    ; build sockaddr_dst for proxy
    mov ax, [ftp_proxy_port]
    xchg al, ah
    mov [sockaddr_dst+2], ax
    mov eax, [ftp_proxy_ip]
    mov [sockaddr_dst+4], eax

    mov rax, SYS_CONNECT
    mov rdi, [ftp_ctrl_fd]
    lea rsi, [sockaddr_dst]
    mov rdx, 16
    syscall
    test rax, rax
    js .close

    call ftp_read_code
    call ftp_send_user
    call ftp_read_code
    call ftp_send_pass
    call ftp_read_code
    call ftp_send_type
    call ftp_read_code

    movzx ecx, word [start_port]
    movzx r15d, word [end_port]
.port_loop:
    cmp ecx, r15d
    ja .close
    call ftp_send_port_cmd
    call ftp_read_code
    call ftp_send_list
    mov eax, 0
    call ftp_read_code
    cmp eax, 150
    je .open
    cmp eax, 125
    je .open
    jmp .closed
.open:
    mov ax, cx
    call record_open
    mov ax, cx
    call write_open_intel
    jmp .next
.closed:
    mov ax, cx
    mov r9, closed_msg
    mov r10d, closed_len
    call write_result
    inc dword [closed_count]
.next:
    inc ecx
    jmp .port_loop

.close:
    mov rax, SYS_CLOSE
    mov rdi, [ftp_ctrl_fd]
    syscall
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ftp_send_user:
    lea rsi, [ftp_user_cmd]
    call ftp_send_cstr
    ret
ftp_send_pass:
    lea rsi, [ftp_pass_cmd]
    call ftp_send_cstr
    ret
ftp_send_type:
    lea rsi, [ftp_type_cmd]
    call ftp_send_cstr
    ret
ftp_send_list:
    lea rsi, [ftp_list_cmd]
    call ftp_send_cstr
    ret

ftp_send_cstr:
    xor edx, edx
.len:
    cmp byte [rsi+rdx], 0
    je .len_done
    inc edx
    jmp .len
.len_done:
    mov rax, SYS_WRITE
    mov rdi, [ftp_ctrl_fd]
    syscall
    ret

; ------------------------------------------------------------
; ftp_send_port_cmd
; Builds "PORT a,b,c,d,p,q"
; ------------------------------------------------------------
ftp_send_port_cmd:
    lea rdi, [ftp_resp_buf]
    mov byte [rdi], 'P'
    mov byte [rdi+1], 'O'
    mov byte [rdi+2], 'R'
    mov byte [rdi+3], 'T'
    mov byte [rdi+4], ' '
    add rdi, 5
    mov eax, [target_ip]
    mov bl, al
    mov bh, ah
    shr eax, 16
    mov cl, al
    mov ch, ah
    movzx edx, bl
    call ftp_append_u8
    mov byte [rdi], ','
    inc rdi
    movzx edx, bh
    call ftp_append_u8
    mov byte [rdi], ','
    inc rdi
    movzx edx, cl
    call ftp_append_u8
    mov byte [rdi], ','
    inc rdi
    movzx edx, ch
    call ftp_append_u8
    mov byte [rdi], ','
    inc rdi
    mov ax, cx
    mov dl, ah
    call ftp_append_u8
    mov byte [rdi], ','
    inc rdi
    movzx edx, al
    call ftp_append_u8
    mov byte [rdi], 13
    mov byte [rdi+1], 10
    mov byte [rdi+2], 0
    lea rsi, [ftp_resp_buf]
    call ftp_send_cstr
    ret

; ------------------------------------------------------------
; ftp_append_u8
; Input: edx = value (0..255), rdi = dst
; Output: rdi advanced
; ------------------------------------------------------------
ftp_append_u8:
    push rax
    mov eax, edx
    cmp eax, 100
    jb .two
    mov ecx, 100
    xor edx, edx
    div ecx
    add al, '0'
    mov [rdi], al
    inc rdi
    mov eax, edx
.two:
    cmp eax, 10
    jb .one
    mov ecx, 10
    xor edx, edx
    div ecx
    add al, '0'
    mov [rdi], al
    inc rdi
    mov eax, edx
.one:
    add al, '0'
    mov [rdi], al
    inc rdi
    pop rax
    ret

; ------------------------------------------------------------
; ftp_read_code
; Returns eax = 3-digit response code or 0
; ------------------------------------------------------------
ftp_read_code:
    mov rax, SYS_READ
    mov rdi, [ftp_ctrl_fd]
    lea rsi, [ftp_resp_buf]
    mov edx, 512
    syscall
    test rax, rax
    jle .zero
    movzx eax, byte [ftp_resp_buf]
    sub eax, '0'
    imul eax, 100
    movzx ebx, byte [ftp_resp_buf+1]
    sub ebx, '0'
    imul ebx, 10
    add eax, ebx
    movzx ebx, byte [ftp_resp_buf+2]
    sub ebx, '0'
    add eax, ebx
    ret
.zero:
    xor eax, eax
    ret

%endif
