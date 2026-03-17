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
    cmp  byte [scan_mode], SCAN_NETBIOS
    jne  .not_netbios
    call netbios_engine_run
    ret
.not_netbios:
    cmp  byte [scan_mode], SCAN_MDNS
    jne  .not_mdns
    call mdns_engine_run
    ret
.not_mdns:
    cmp  byte [scan_mode], SCAN_SNMP
    jne  .not_snmp
    call snmp_engine_run
    ret
.not_snmp:
    cmp  byte [scan_mode], SCAN_SMB
    jne  .not_smb
    call smb_engine_run
    ret
.not_smb:
    cmp  byte [scan_mode], SCAN_SSL
    jne  .not_ssl
    call ssl_engine_run
    ret
.not_ssl:
    cmp  byte [scan_mode], SCAN_HTTP
    jne  .not_http
    call http_engine_run
    ret
.not_http:
    cmp  byte [scan_mode], SCAN_DNS
    jne  .not_dns
    call dns_engine_run
    ret
.not_dns:
    cmp  byte [scan_mode], SCAN_NTP
    jne  .not_ntp
    call ntp_engine_run
    ret
.not_ntp:
    cmp  byte [scan_mode], SCAN_REDIS
    jne  .not_redis
    call redis_engine_run
    ret
.not_redis:
    cmp  byte [scan_mode], SCAN_MEMCACHED
    jne  .not_memcached
    call memcached_engine_run
    ret
.not_memcached:
    cmp  byte [scan_mode], SCAN_DEEP
    jne  .not_deep
    call deep_probe_engine_run
    ret
.not_deep:
    cmp  byte [scan_mode], SCAN_HEARTBLEED
    jne  .not_heartbleed
    call ssl_engine_run
    ret
.not_heartbleed:
    cmp  byte [scan_mode], SCAN_QUIC
    jne  .not_quic
    call quic_engine_run
    ret
.not_quic:
    cmp  byte [scan_mode], SCAN_MQTT
    jne  .not_mqtt
    call mqtt_stub_run
    ret
.not_mqtt:
    cmp  byte [scan_mode], SCAN_MODBUS
    jne  .not_modbus
    call ics_engine_run
    ret
.not_modbus:
    cmp  byte [scan_mode], SCAN_S7
    jne  .not_s7
    call ics_engine_run
    ret
.not_s7:
    cmp  byte [scan_mode], SCAN_BACNET
    jne  .not_bacnet
    call ics_engine_run
    ret
.not_bacnet:
    cmp  byte [scan_mode], SCAN_UPNP
    jne  .not_upnp
    call upnp_engine_run
    ret
.not_upnp:
    cmp  byte [scan_mode], SCAN_TELNET
    jne  .not_telnet
    call telnet_engine_run
    ret
.not_telnet:
    cmp  byte [scan_mode], SCAN_VNC
    jne  .not_vnc
    call vnc_engine_run
    ret
.not_vnc:
    cmp  byte [scan_mode], SCAN_RDP
    jne  .not_rdp
    call rdp_engine_run
    ret
.not_rdp:
    cmp  byte [scan_mode], SCAN_AMQP
    jne  .not_amqp
    call amqp_stub_run
    ret
.not_amqp:
    cmp  byte [scan_mode], SCAN_MSSQL
    jne  .not_mssql
    call db_engine_run
    ret
.not_mssql:
    cmp  byte [scan_mode], SCAN_MYSQL
    jne  .not_mysql
    call db_engine_run
    ret
.not_mysql:
    cmp  byte [scan_mode], SCAN_POSTGRES
    jne  .not_pg
    call db_engine_run
    ret
.not_pg:
    cmp  byte [scan_mode], SCAN_MONGO
    jne  .not_mongo
    call db_engine_run
    ret
.not_mongo:
    cmp  byte [scan_mode], SCAN_ELASTIC
    jne  .not_elastic
    call db_engine_run
    ret
.not_elastic:
    cmp  byte [scan_mode], SCAN_LDAP
    jne  .not_ldap
    call db_engine_run
    ret
.not_ldap:
    cmp  byte [scan_mode], SCAN_KERBEROS
    jne  .not_krb
    call db_engine_run
    ret
.not_krb:
    cmp  byte [scan_mode], SCAN_WINRM
    jne  .not_winrm
    call db_engine_run
    ret
.not_winrm:
    cmp  byte [scan_mode], SCAN_KAFKA
    jne  .not_kafka
    call kafka_stub_run
    ret
.not_kafka:
    cmp  byte [scan_mode], SCAN_DNP3
    jne  .not_dnp3
    call ics_engine_run
    ret
.not_dnp3:
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

