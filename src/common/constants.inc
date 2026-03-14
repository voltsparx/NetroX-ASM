%ifndef CONSTANTS_INC
%define CONSTANTS_INC 1

; Linux syscall numbers (x86_64)
%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_OPEN 2
%define SYS_CLOSE 3
%define SYS_SOCKET 41
%define SYS_CONNECT 42
%define SYS_ACCEPT 43
%define SYS_SENDTO 44
%define SYS_RECVFROM 45
%define SYS_GETSOCKNAME 51
%define SYS_SETSOCKOPT 54
%define SYS_EPOLL_CREATE1 291
%define SYS_EPOLL_CTL 233
%define SYS_EPOLL_WAIT 232
%define SYS_CLOCK_GETTIME 228
%define SYS_IOCTL 16
%define SYS_EXIT 60

; Socket constants
%define AF_INET 2
%define AF_PACKET 17
%define SOCK_RAW 3
%define SOCK_DGRAM 2
%define IPPROTO_IP 0
%define IPPROTO_TCP 6
%define IPPROTO_UDP 17
%define IP_HDRINCL 3
%define ETH_P_IP 0x0800
%define ETH_P_IP_BE 0x0008
%define SOL_SOCKET 1
%define SO_RCVTIMEO 20
%define EPOLLIN 0x001
%define EPOLLET 0x80000000
%define EPOLL_CTL_ADD 1
%define CLOCK_MONOTONIC 1
%define SIOCGIFINDEX 0x8933
%define SIOCGIFFLAGS 0x8913
%define IFF_UP 0x1
%define IFF_RUNNING 0x40

%endif
