%ifndef ENGINE_INC
%define ENGINE_INC 1

%define ENGINE_SYN 1
%define ENGINE_UDP 2
%define ENGINE_ICMP 3
%define ENGINE_L2 4

; build_packet dispatches based on engine_id
build_packet:
    mov al, [engine_id]
    cmp al, ENGINE_SYN
    je build_syn_packet
    jmp build_syn_packet

%endif
