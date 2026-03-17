%ifndef SCAN_INC
%define SCAN_INC 1

; ============================================================
; TCP flag-based scan modes
; ============================================================
%define SCAN_SYN        1       ; SYN only               flags=0x02
%define SCAN_ACK        2       ; ACK only               flags=0x10
%define SCAN_FIN        3       ; FIN only               flags=0x01
%define SCAN_NULL       4       ; No flags               flags=0x00
%define SCAN_XMAS       5       ; FIN+PSH+URG            flags=0x29
%define SCAN_WINDOW     6       ; ACK (window inspect)   flags=0x10
%define SCAN_MAIMON     7       ; FIN+ACK                flags=0x11
%define SCAN_UDP        8       ; UDP datagram scan
%define SCAN_PING       9       ; ICMP echo scan
%define SCAN_SAR        10      ; SAR resonance scan
%define SCAN_KIS        11      ; KIS impedance scan
%define SCAN_PHANTOM    12      ; Phantom scan
%define SCAN_CALLBACK   13      ; Callback-Ping scan
%define SCAN_CONNECT    14      ; TCP connect scan
%define SCAN_IDLE       15      ; Idle/zombie scan
%define SCAN_IPROTO     16      ; IP protocol scan
%define SCAN_PINGSWEEP  17      ; Ping sweep
%define SCAN_LIST       18      ; List scan
%define SCAN_RPC        19      ; RPC scan
%define SCAN_SCTP_INIT  20      ; SCTP INIT scan
%define SCAN_SCTP_ECHO  21      ; SCTP COOKIE-ECHO scan
%define SCAN_FTP_BOUNCE 22      ; FTP bounce scan
%define SCAN_SCRIPT     23      ; Script/inline probes
%define SCAN_AGGRESSIVE 24      ; Aggressive scan
%define SCAN_SEQ        25      ; Sequential scan order
%define SCAN_ICMP_TS    26      ; ICMP timestamp
%define SCAN_ICMP_NM    27      ; ICMP netmask
%define SCAN_ARP        28      ; ARP scan

%define SCAN_NETBIOS    29    ; UDP 137 NetBIOS Name Service
%define SCAN_MDNS       30    ; mDNS/DNS-SD on 224.0.0.251:5353
%define SCAN_SNMP       31    ; UDP 161 SNMP GetRequest
%define SCAN_SMB        32    ; TCP 445 SMB NEGOTIATE
%define SCAN_SSL        33    ; TLS ClientHello + cert parse
%define SCAN_HTTP       34    ; TCP HTTP GET + banner
%define SCAN_DNS        35    ; DNS version/AXFR/recursion probes
%define SCAN_NTP        36    ; UDP 123 NTP version + monlist
%define SCAN_REDIS      37    ; TCP 6379 Redis PING + INFO
%define SCAN_MEMCACHED  38    ; TCP/UDP 11211 Memcached version + stats
%define SCAN_DEEP       39    ; post-scan deep probe orchestrator
%define SCAN_HEARTBLEED 40    ; TLS Heartbleed detection


%define SCAN_QUIC       41    ; QUIC/HTTP3 on UDP 443
%define SCAN_MQTT       42    ; MQTT on TCP 1883
%define SCAN_MODBUS     43    ; Modbus/TCP on TCP 502
%define SCAN_S7         44    ; Siemens S7 on TCP 102
%define SCAN_BACNET     45    ; BACnet/IP on UDP 47808
%define SCAN_UPNP       46    ; UPnP/SSDP on UDP 1900
%define SCAN_TELNET     47    ; Telnet on TCP 23
%define SCAN_VNC        48    ; VNC on TCP 5900
%define SCAN_RDP        49    ; RDP on TCP 3389
%define SCAN_AMQP       50    ; AMQP on TCP 5672
%define SCAN_MSSQL      51    ; MSSQL TDS on TCP 1433
%define SCAN_MYSQL      52    ; MySQL on TCP 3306
%define SCAN_POSTGRES   53    ; PostgreSQL on TCP 5432
%define SCAN_MONGO      54    ; MongoDB on TCP 27017
%define SCAN_ELASTIC    55    ; Elasticsearch on TCP 9200
%define SCAN_LDAP       56    ; LDAP on TCP 389
%define SCAN_KERBEROS   57    ; Kerberos on TCP/UDP 88
%define SCAN_WINRM      58    ; WinRM on TCP 5985
%define SCAN_KAFKA      59    ; Kafka on TCP 9092
%define SCAN_DNP3       60    ; DNP3 on TCP 20000

%endif

