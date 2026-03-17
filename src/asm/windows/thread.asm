
; ============================================================
; NetroX-ASC Hybrid | Windows thread entry (TX/RX)
; ============================================================
%ifndef THREAD_WINDOWS_ASM
%define THREAD_WINDOWS_ASM 1

default rel

SECTION .bss
win_tx_handle  resq 1
win_rx_handle  resq 1

SECTION .text

global asm_start_tx_thread
global asm_start_rx_thread

extern tx_loop_entry
extern rx_loop_entry
extern CloseHandle
extern CreateThread

; ------------------------------------------------------------
; asm_start_tx_thread(ScanConfig* cfg) -> handle (non-zero) / 0 on fail
; ------------------------------------------------------------
asm_start_tx_thread:
    ; CreateThread(lpThreadAttributes=NULL, dwStackSize=0,
    ;              lpStartAddress=tx_loop_entry, lpParameter=cfg,
    ;              dwCreationFlags=0, lpThreadId=NULL)
    sub  rsp, 40
    xor  rcx, rcx
    xor  rdx, rdx
    lea  r8, [tx_loop_entry]
    mov  r9, rdi
    mov  qword [rsp+32], 0
    call CreateThread
    add  rsp, 40
    mov  [win_tx_handle], rax
    ret

; ------------------------------------------------------------
; asm_start_rx_thread(ScanConfig* cfg) -> handle (non-zero) / 0 on fail
; ------------------------------------------------------------
asm_start_rx_thread:
    sub  rsp, 40
    xor  rcx, rcx
    xor  rdx, rdx
    lea  r8, [rx_loop_entry]
    mov  r9, rdi
    mov  qword [rsp+32], 0
    call CreateThread
    add  rsp, 40
    mov  [win_rx_handle], rax
    ret

%endif
