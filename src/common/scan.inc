%ifndef SCAN_INC
%define SCAN_INC 1

; ============================================================
; TCP flag-based scan modes
; ============================================================
%define SCAN_SYN        1       ; SYN only            flags=0x02
%define SCAN_ACK        2       ; ACK only            flags=0x10
%define SCAN_FIN        3       ; FIN only            flags=0x01
%define SCAN_NULL       4       ; No flags            flags=0x00
%define SCAN_XMAS       5       ; FIN+PSH+URG         flags=0x29
%define SCAN_WINDOW     6       ; ACK (window inspect) flags=0x10
%define SCAN_MAIMON     7       ; FIN+ACK             flags=0x11
%define SCAN_UDP        8       ; UDP datagram scan
%define SCAN_PING       9       ; ICMP echo scan
%define SCAN_SAR        10      ; SAR resonance scan
%define SCAN_KIS        11      ; KIS impedance scan
%define SCAN_PHANTOM    12      ; Phantom scan

%endif
