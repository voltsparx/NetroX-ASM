%ifndef CONSTANTS_INC
%define CONSTANTS_INC 1

; ============================================================
; Linux syscall numbers (x86_64)
; ============================================================
%define SYS_READ            0
%define SYS_WRITE           1
%define SYS_OPEN            2
%define SYS_CLOSE           3
%define SYS_SOCKET          41
%define SYS_CONNECT         42
%define SYS_ACCEPT          43
%define SYS_SENDTO          44
%define SYS_RECVFROM        45
%define SYS_GETSOCKNAME     51
%define SYS_SETSOCKOPT      54
%define SYS_EPOLL_CREATE1   291
%define SYS_EPOLL_CTL       233
%define SYS_EPOLL_WAIT      232
%define SYS_CLOCK_GETTIME   228
%define SYS_IOCTL           16
%define SYS_EXIT            60

; ============================================================
; Address families
; ============================================================
%define AF_INET             2
%define AF_PACKET           17

; ============================================================
; Socket types
; ============================================================
%define SOCK_STREAM         1
%define SOCK_DGRAM          2
%define SOCK_RAW            3

; ============================================================
; IP protocols
; ============================================================
%define IPPROTO_IP          0
%define IPPROTO_ICMP        1
%define IPPROTO_TCP         6
%define IPPROTO_UDP         17
%define IPPROTO_SCTP        132

; ============================================================
; Socket options
; ============================================================
%define IP_HDRINCL          3
%define SOL_SOCKET          1
%define SO_RCVTIMEO         20
%define MSG_MORE            0x8000

; ============================================================
; Ethernet protocol numbers (host and network byte order)
; ============================================================
%define ETH_P_IP            0x0800
%define ETH_P_IP_BE         0x0008      ; big-endian for AF_PACKET bind

; ============================================================
; epoll constants
; ============================================================
%define EPOLLIN             0x00000001
%define EPOLLET             0x80000000
%define EPOLL_CTL_ADD       1
%define EPOLL_CTL_DEL       2
%define EPOLL_CTL_MOD       3

; ============================================================
; Clock IDs (clock_gettime)
; ============================================================
%define CLOCK_REALTIME      0
%define CLOCK_MONOTONIC     1

; ============================================================
; ioctl codes for network interface queries
; ============================================================
%define SIOCGIFINDEX        0x8933
%define SIOCGIFFLAGS        0x8913
%define SIOCGIFADDR         0x8915

; ============================================================
; Interface flags (from if.h)
; ============================================================
%define IFF_UP              0x0001
%define IFF_BROADCAST       0x0002
%define IFF_LOOPBACK        0x0008
%define IFF_RUNNING         0x0040
%define IFF_PROMISC         0x0100

; ============================================================
; ICMP types
; ============================================================
%define ICMP_ECHO_REPLY     0
%define ICMP_DEST_UNREACH   3
%define ICMP_ECHO_REQUEST   8
%define ICMP_TIME_EXCEEDED  11

; ============================================================
; ICMP codes (used with ICMP_DEST_UNREACH)
; ============================================================
%define ICMP_PORT_UNREACH   3

%endif
