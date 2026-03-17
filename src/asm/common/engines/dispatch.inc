%ifndef ENGINES_DISPATCH_INC
%define ENGINES_DISPATCH_INC 1

%include "colors.inc"

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
%include "engines/callback_engine.inc"
%include "engines/connect_engine.inc"
%include "engines/idle_engine.inc"
%include "engines/iproto_engine.inc"
%include "engines/pingsweep_engine.inc"
%include "engines/list_engine.inc"
%include "engines/rpc_engine.inc"
%include "engines/sctp_init_engine.inc"
%include "engines/sctp_echo_engine.inc"
%include "engines/ftp_bounce_engine.inc"
%include "engines/script_engine.inc"
%include "engines/aggressive_engine.inc"
%include "engines/seq_engine.inc"
%include "engines/icmp_ts_engine.inc"
%include "engines/icmp_nm_engine.inc"
%include "engines/arp_engine.inc"

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

%include "engines/netbios_engine.inc"
%include "engines/mdns_engine.inc"
%include "engines/snmp_engine.inc"
%include "engines/smb_engine.inc"
%include "engines/ssl_engine.inc"
%include "engines/http_engine.inc"
%include "engines/dns_engine.inc"
%include "engines/ntp_engine.inc"
%include "engines/kvdb_engine.inc"
%include "engines/memcached_engine.inc"
%include "engines/deep_engine.inc"

%include "engines/quic_engine.inc"
%include "engines/ics_engine.inc"
%include "engines/db_engine.inc"
%include "engines/upnp_engine.inc"
%include "engines/telnet_engine.inc"
%include "engines/vnc_engine.inc"
%include "engines/rdp_engine.inc"
%include "engines/mqtt_engine.inc"
%include "engines/amqp_engine.inc"
%include "engines/kafka_engine.inc"

%endif


