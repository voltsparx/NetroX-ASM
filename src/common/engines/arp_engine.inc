; ============================================================
; arp_engine.inc - scan engine (stub)
; ============================================================

%ifndef ARP_ENGINE_INC
%define ARP_ENGINE_INC 1

SECTION .text

; ------------------------------------------------------------
; arp_run
; ARP scan for local subnet (single target_ip if no CIDR)
; ------------------------------------------------------------
arp_run:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; open AF_PACKET socket for ARP
    mov rax, SYS_SOCKET
    mov rdi, AF_PACKET
    mov rsi, SOCK_RAW
    mov rdx, ETH_P_ARP_BE
    syscall
    test rax, rax
    js .done
    mov [arp_sock_fd], rax

    ; fetch MAC via SIOCGIFHWADDR
    lea rdi, [ifreq_buf]
    xor eax, eax
    mov rcx, 5
    rep stosq
    lea rsi, [iface_name]
    lea rdi, [ifreq_buf]
    mov rcx, 16
.cpy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .cpy_done
    inc rsi
    inc rdi
    loop .cpy
.cpy_done:
    mov rax, SYS_IOCTL
    mov rdi, [arp_sock_fd]
    mov rsi, SIOCGIFHWADDR
    lea rdx, [ifreq_buf]
    syscall
    ; hwaddr at ifreq_buf+18
    lea rsi, [ifreq_buf+18]
    lea rdi, [arp_mac_addr]
    mov ecx, 6
    rep movsb

    ; build sockaddr_ll for ARP
    mov word [sockaddr_ll], AF_PACKET
    mov word [sockaddr_ll+2], ETH_P_ARP_BE
    mov eax, [ifindex]
    mov [sockaddr_ll+4], eax

    cmp byte [cidr_mode], 1
    jne .single
    xor r12d, r12d
.range_loop:
    cmp r12d, [ip_range_count]
    jae .done_send
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
    call arp_probe_ip
    inc ebx
    jmp .host_loop
.next_range:
    inc r12d
    jmp .range_loop

.single:
    mov eax, [target_ip]
    mov [current_scan_ip], eax
    call arp_probe_ip

.done_send:
    mov rax, SYS_CLOSE
    mov rdi, [arp_sock_fd]
    syscall
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ------------------------------------------------------------
; arp_probe_ip
; current_scan_ip set
; ------------------------------------------------------------
arp_probe_ip:
    push rbx

    ; ethernet header
    mov qword [arp_buf+0], 0xFFFFFFFFFFFFFFFF
    mov word  [arp_buf+8], 0xFFFF
    lea rsi, [arp_mac_addr]
    lea rdi, [arp_buf+6]
    mov ecx, 6
    rep movsb
    mov word [arp_buf+12], 0x0608   ; ARP ethertype

    ; ARP payload
    mov word [arp_buf+14], 0x0100   ; htype=1
    mov word [arp_buf+16], 0x0008   ; ptype=0x0800
    mov byte [arp_buf+18], 6
    mov byte [arp_buf+19], 4
    mov word [arp_buf+20], 0x0100   ; op=1
    lea rsi, [arp_mac_addr]
    lea rdi, [arp_buf+22]
    mov ecx, 6
    rep movsb
    mov eax, [source_ip]
    mov [arp_buf+28], eax
    mov qword [arp_buf+32], 0
    mov eax, [current_scan_ip]
    mov [arp_buf+38], eax

    ; send ARP
    mov rax, SYS_SENDTO
    mov rdi, [arp_sock_fd]
    lea rsi, [arp_buf]
    mov edx, 42
    xor r10d, r10d
    lea r8, [sockaddr_ll]
    mov r9d, 32
    syscall

    ; wait for reply
    mov rax, SYS_RECVFROM
    mov rdi, [arp_sock_fd]
    lea rsi, [recv_buf]
    mov edx, 4096
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    syscall
    test rax, rax
    jle .arp_done

    ; check ARP reply
    cmp word [recv_buf+12], 0x0608
    jne .arp_done
    cmp word [recv_buf+20], 0x0200
    jne .arp_done
    mov eax, [recv_buf+28]
    cmp eax, [current_scan_ip]
    jne .arp_done

    ; mark host as open
    mov ax, 0
    call write_open_intel

.arp_done:
    pop rbx
    ret

%endif
