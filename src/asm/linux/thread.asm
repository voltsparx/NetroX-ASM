BITS 64
DEFAULT REL
GLOBAL asm_start_tx_thread, asm_start_rx_thread

%include "../common/constants.inc"
%include "../common/scan.inc"

SECTION .bss
tx_stack        resb 65536
rx_stack        resb 65536
tx_tid          resd 1
rx_tid          resd 1

SECTION .text

asm_start_tx_thread:
    push rbx
    mov  rbx, rdi
    lea  rsi, [tx_stack + 65536 - 8]
    and  rsi, -16
    
    mov  [rsi], rdi
    mov  eax, 56
    mov  edi, 0x00010F00
    xor  edx, edx
    xor  ecx, ecx
    lea  r8, [tx_thread_entry]
    mov  r9, rbx
    syscall
    pop  rbx
    ret

tx_thread_entry:
    mov  [cfg_ptr], rdi
    call tx_loop_entry
    mov  eax, 60
    xor  edi, edi
    syscall

asm_start_rx_thread:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rx_stack + 65536 - 8]
    and  rsi, -16
    mov  [rsi], rdi
    mov  eax, 56
    mov  edi, 0x00010F00
    xor  edx, edx
    xor  ecx, ecx
    lea  r8, [rx_thread_entry]
    syscall
    pop  rbx
    ret

rx_thread_entry:
    mov  [cfg_ptr], rdi
    call rx_loop_entry
    mov  eax, 60
    xor  edi, edi
    syscall
