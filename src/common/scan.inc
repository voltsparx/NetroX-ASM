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

%endif
