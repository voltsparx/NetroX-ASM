; ============================================================
; NetroX-ASC Hybrid | Linux network helpers (WIP extraction)
; ============================================================
%ifndef NETWORK_LINUX_ASM
%define NETWORK_LINUX_ASM 1

default rel

SECTION .text
global asm_host_probe
global asm_get_local_ip_internal
global copy_iface_name
global setup_send_engine
global verify_iface
global setup_sigint_handler
global asm_setup_tx_ring
global sigint_handler

; -------------------------------------------------------------------
; copy_iface_name  rsi=src  -> eax=0 ok, 1 too long
; -------------------------------------------------------------------
copy_iface_name:
    push rbx
    lea rdi, [iface_name]
    xor eax, eax
    mov rcx, 16
    rep stosb
    lea rdi, [iface_name]
    mov rcx, 15
.copy:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ok
    inc rsi
    inc rdi
    dec rcx
    jnz .copy
    pop rbx
    mov eax, 1
    ret
.ok:
    pop rbx
    xor eax, eax
    ret

; -------------------------------------------------------------------
; setup_send_engine
; -------------------------------------------------------------------
setup_send_engine:
    cmp byte [iface_set], 0
    je .use_raw
    call verify_iface
    test eax, eax
    jnz .fail
    mov rax, SYS_SOCKET
    mov rdi, AF_PACKET
    mov rsi, SOCK_DGRAM
    mov rdx, ETH_P_IP_BE
    syscall
    test rax, rax
    js .fail
    mov [send_fd], rax
    mov word [sockaddr_ll], AF_PACKET
    mov word [sockaddr_ll+2], ETH_P_IP_BE
    mov eax, [ifindex]
    mov [sockaddr_ll+4], eax
    mov byte [engine_id], ENGINE_L2
    xor eax, eax
    ret
.use_raw:
    mov rax, [raw_fd]
    mov [send_fd], rax
    xor eax, eax
    ret
.fail:
    mov eax, 1
    ret

; -------------------------------------------------------------------
; verify_iface
; -------------------------------------------------------------------
verify_iface:
    push rbx
    lea rdi, [ifreq_buf]
    xor eax, eax
    mov rcx, 5
    rep stosq
    lea rsi, [iface_name]
    lea rdi, [ifreq_buf]
    mov rcx, 16
.copy_ifr:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .ifr_copied
    inc rsi
    inc rdi
    dec rcx
    jnz .copy_ifr
    jmp .fail_pop

.ifr_copied:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .fail_pop
    mov rbx, rax

    mov rax, SYS_IOCTL
    mov rdi, rbx
    mov rsi, SIOCGIFINDEX
    lea rdx, [ifreq_buf]
    syscall
    test rax, rax
    js .fail_close
    mov eax, [ifreq_buf+16]
    mov [ifindex], eax

    mov rax, SYS_IOCTL
    mov rdi, rbx
    mov rsi, SIOCGIFFLAGS
    lea rdx, [ifreq_buf]
    syscall
    test rax, rax
    js .fail_close
    mov ax, [ifreq_buf+16]
    test ax, IFF_UP
    jz .fail_close
    test ax, IFF_RUNNING
    jz .fail_close

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    pop rbx
    xor eax, eax
    ret

.fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fail_pop:
    pop rbx
    mov eax, 1
    ret

; -------------------------------------------------------------------
; get_local_ip
; -------------------------------------------------------------------
asm_get_local_ip_internal:
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_DGRAM
    mov rdx, IPPROTO_UDP
    syscall
    test rax, rax
    js .fail
    mov rbx, rax

    mov word  [sockaddr_tmp],   AF_INET
    mov word  [sockaddr_tmp+2], 0x3500
    mov eax, [target_ip]
    mov [sockaddr_tmp+4], eax

    mov rax, SYS_CONNECT
    mov rdi, rbx
    lea rsi, [sockaddr_tmp]
    mov rdx, 16
    syscall
    test rax, rax
    js .fail_close

    mov dword [addrlen], 16
    mov rax, SYS_GETSOCKNAME
    mov rdi, rbx
    lea rsi, [sockaddr_local]
    lea rdx, [addrlen]
    syscall
    test rax, rax
    js .fail_close

    mov eax, [sockaddr_local+4]
    mov [source_ip], eax

    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    xor eax, eax
    ret

.fail_close:
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
.fail:
    mov eax, 1
    ret

; -------------------------------------------------------------------
; asm_host_probe (ICMP echo, no output)
; -------------------------------------------------------------------
asm_host_probe:
    push rbx
    push r12
    mov r12b, [engine_id]
    mov bl, [scan_mode]
    mov byte [engine_id], ENGINE_ICMP
    xor ax, ax
    mov [dst_port_be], ax
    call build_icmp_packet
    call intel_rtt_start

    mov rax, SYS_SENDTO
    mov rdi, [raw_fd]
    lea rsi, [packet_buf]
    mov edx, 60
    xor r10, r10
    lea r8, [sockaddr_dst]
    mov r9, 16
    syscall

    mov byte [host_up_map], 0
    mov rax, SYS_EPOLL_WAIT
    mov rdi, [epoll_fd]
    lea rsi, [epoll_out]
    mov rdx, 1
    mov r10, 2000
    syscall
    test rax, rax
    jle .restore

    mov rax, SYS_RECVFROM
    mov rdi, [raw_fd]
    lea rsi, [recv_buf]
    mov rdx, 4096
    xor r10, r10
    xor r8, r8
    xor r9, r9
    syscall
    test rax, rax
    js .restore

    lea rsi, [recv_buf]
    mov al, [rsi+9]
    cmp al, 1
    jne .restore
    mov eax, [rsi+12]
    cmp eax, [target_ip]
    jne .restore
    mov al, [rsi+20]
    cmp al, 0
    jne .restore
    mov byte [host_up_map], 1
    mov al, [rsi+8]
    mov [last_ttl], al
    call intel_rtt_record

.restore:
    mov [engine_id], r12b
    mov [scan_mode], bl
    pop r12
    pop rbx
    ret

; -------------------------------------------------------------------
; setup_sigint_handler
; -------------------------------------------------------------------
setup_sigint_handler:
    sub  rsp, 152
    lea  rax, [sigint_handler]
    mov  [rsp], rax
    mov  qword [rsp+8], 0
    mov  qword [rsp+16], 0
    mov  rax, SYS_RT_SIGACTION
    mov  rdi, SIGINT
    mov  rsi, rsp
    xor  rdx, rdx
    mov  r10, 8
    syscall
    add  rsp, 152
    ret

sigint_handler:
    mov byte [scan_done_flag], 1
    ret

%include "../common/constants.inc"
%include "../common/packet.inc"
%include "../common/checksum.inc"
%include "../common/intelligence.inc"


; -------------------------------------------------------------------
; asm_setup_tx_ring
; rdi = ScanConfig*
; -------------------------------------------------------------------
asm_setup_tx_ring:
    push rbx
    mov  rbx, rdi

    mov  eax, SYS_SOCKET
    mov  edi, AF_PACKET
    mov  esi, SOCK_RAW
    mov  edx, ETH_P_ALL
    syscall
    test eax, eax
    js   .ring_fail
    mov  [tx_ring_fd], eax

    sub  rsp, 16
    mov  dword [rsp+0], 1048576
    mov  dword [rsp+4], 16
    mov  dword [rsp+8], 2048
    mov  dword [rsp+12], 8192

    mov  eax, SYS_SETSOCKOPT
    mov  edi, [tx_ring_fd]
    mov  esi, SOL_PACKET
    mov  edx, PACKET_TX_RING
    mov  r10, rsp
    mov  r8d, 16
    syscall
    add  rsp, 16
    test eax, eax
    js   .ring_fail

    mov  eax, 9
    xor  edi, edi
    mov  esi, 16777216
    mov  edx, 3
    mov  r10d, 1
    mov  r8d, [tx_ring_fd]
    xor  r9d, r9d
    syscall
    cmp  rax, -1
    je   .ring_fail
    mov  [tx_ring_ptr], rax
    mov  dword [tx_ring_frames], 8192
    xor  eax, eax
    pop  rbx
    ret

.ring_fail:
    neg  eax
    pop  rbx
    ret
%endif




