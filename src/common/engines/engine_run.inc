%ifndef ENGINE_RUN_INC
%define ENGINE_RUN_INC 1

%ifndef ENGINE_MODE_SEQ
%define ENGINE_MODE_SEQ       1
%define ENGINE_MODE_ASYNC     2
%define ENGINE_MODE_PARALLEL  3
%define ENGINE_MODE_THREADED  4
%define ENGINE_MODE_SCHED     5
%define ENGINE_MODE_PIPELINE  6
%define ENGINE_MODE_BATCH     7
%define ENGINE_MODE_HYBRID    8
%endif

engine_run:
    movzx eax, byte [engine_mode]
    cmp al, ENGINE_MODE_ASYNC
    je engine_async_run
    cmp al, ENGINE_MODE_PIPELINE
    je engine_pipeline_run
    cmp  byte [scan_mode], SCAN_SAR
    jne  .not_sar
    call sar_run
    ret
.not_sar:
    cmp  byte [scan_mode], SCAN_KIS
    jne  .not_kis
    call kis_run
    ret
.not_kis:
    cmp  byte [scan_mode], SCAN_PHANTOM
    jne  .not_phantom
    call phantom_run
    ret
.not_phantom:
    cmp  byte [scan_mode], SCAN_CALLBACK
    jne  .not_callback
    call cb_run
    ret
.not_callback:
    cmp  byte [scan_mode], SCAN_CONNECT
    jne  .not_connect
    call connect_run
    ret
.not_connect:
    cmp  byte [scan_mode], SCAN_IDLE
    jne  .not_idle
    call idle_run
    ret
.not_idle:
    cmp  byte [scan_mode], SCAN_IPROTO
    jne  .not_iproto
    call iproto_run
    ret
.not_iproto:
    cmp  byte [scan_mode], SCAN_PINGSWEEP
    jne  .not_pingsweep
    call pingsweep_run
    ret
.not_pingsweep:
    cmp  byte [scan_mode], SCAN_LIST
    jne  .not_list
    call list_run
    ret
.not_list:
    cmp  byte [scan_mode], SCAN_RPC
    jne  .not_rpc
    call rpc_run
    ret
.not_rpc:
    cmp  byte [scan_mode], SCAN_SCTP_INIT
    jne  .not_sctp_init
    call sctp_init_run
    ret
.not_sctp_init:
    cmp  byte [scan_mode], SCAN_SCTP_ECHO
    jne  .not_sctp_echo
    call sctp_echo_run
    ret
.not_sctp_echo:
    cmp  byte [scan_mode], SCAN_FTP_BOUNCE
    jne  .not_ftp
    call ftp_bounce_run
    ret
.not_ftp:
    cmp  byte [scan_mode], SCAN_SCRIPT
    jne  .not_script
    call script_run
    ret
.not_script:
    cmp  byte [scan_mode], SCAN_AGGRESSIVE
    jne  .not_aggressive
    call aggressive_run
    ret
.not_aggressive:
    cmp  byte [scan_mode], SCAN_SEQ
    jne  .not_seq
    call seq_run
    ret
.not_seq:
    cmp  byte [scan_mode], SCAN_ICMP_TS
    jne  .not_icmp_ts
    call icmp_ts_run
    ret
.not_icmp_ts:
    cmp  byte [scan_mode], SCAN_ICMP_NM
    jne  .not_icmp_nm
    call icmp_nm_run
    ret
.not_icmp_nm:
    cmp  byte [scan_mode], SCAN_ARP
    jne  .not_arp
    call arp_run
    ret
.not_arp:
    ret

print_engine_status:
    cmp byte [prompt_mode], 0
    jne .silent
    lea rsi, [eng_status_msg]
    xor edx, edx
.eng_str_len:
    cmp byte [rsi+rdx], 0
    je .eng_str_done
    inc edx
    jmp .eng_str_len
.eng_str_done:
    call buf_write
    movzx eax, byte [engine_mode]
    cmp al, ENGINE_MODE_ASYNC
    je .print_async
    cmp al, ENGINE_MODE_PIPELINE
    je .print_pipe
    cmp al, ENGINE_MODE_HYBRID
    je .print_hybrid
    lea rsi, [eng_seq_str]
    jmp .print_name
.print_async:
    lea rsi, [eng_async_str]
    jmp .print_name
.print_hybrid:
    lea rsi, [eng_hybrid_str]
    jmp .print_name
.print_pipe:
    lea rsi, [eng_pipe_str]
    xor edx, edx
.pipe_name_len:
    cmp byte [rsi+rdx], 0
    je .pipe_name_done
    inc edx
    jmp .pipe_name_len
.pipe_name_done:
    call buf_write
    movzx ax, word [pipe_depth]
    call append_u16
    lea rsi, [eng_paren_close]
    mov edx, 3
    call buf_write
    jmp .silent
.print_name:
    xor edx, edx
.name_len:
    cmp byte [rsi+rdx], 0
    je .name_done
    inc edx
    jmp .name_len
.name_done:
    call buf_write
.silent:
    ret

%endif
