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
