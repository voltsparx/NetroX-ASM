%ifndef ENGINES_DISPATCH_INC
%define ENGINES_DISPATCH_INC 1

%include "engines/inflight.inc"
%include "engines/demux.inc"
%include "engines/tcp_engine.inc"
%include "engines/icmp_engine.inc"
%include "engines/async_engine.inc"
%include "engines/pipeline_engine.inc"
%include "engines/engine_run.inc"
%include "engines/sar_engine.inc"
%include "engines/kis_engine.inc"
%include "engines/phantom_engine.inc"

; ============================================================
; Engine IDs  -  stored in engine_id (.bss byte)
; ============================================================
%define ENGINE_SYN      1
%define ENGINE_UDP      2
%define ENGINE_ICMP     3
%define ENGINE_L2       4

; ============================================================
; build_packet
; ============================================================
build_packet:
    mov  al, [engine_id]
    cmp  al, ENGINE_ICMP
    je   build_icmp_packet
    cmp  al, ENGINE_UDP
    je   build_udp_packet
    jmp  build_syn_packet

%endif
