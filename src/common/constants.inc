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
%define SYS_RT_SIGACTION    13

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
%define SO_SNDTIMEO         21
%define MSG_MORE            0x8000
%define O_WRONLY            1
%define O_CREAT             64
%define O_TRUNC             512

; ============================================================
; Ethernet protocol numbers (host and network byte order)
; ============================================================
%define ETH_P_IP            0x0800
%define ETH_P_IP_BE         0x0008      ; big-endian for AF_PACKET bind
%define ETH_P_ARP_BE        0x0608

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
%define SIOCGIFHWADDR       0x8927

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

; ============================================================
; Execution engine mode constants
; ============================================================
%define ENGINE_MODE_SEQ       1
%define ENGINE_MODE_ASYNC     2
%define ENGINE_MODE_PARALLEL  3
%define ENGINE_MODE_THREADED  4
%define ENGINE_MODE_SCHED     5
%define ENGINE_MODE_PIPELINE  6
%define ENGINE_MODE_BATCH     7
%define ENGINE_MODE_HYBRID    8

; ============================================================
; Async engine constants
; ============================================================
%define ASYNC_BURST           64
%define ASYNC_RECV_MAX        32

; ============================================================
; Pipeline engine constants
; ============================================================
%define PIPELINE_MAX_DEPTH    512

; ============================================================
; In-flight tracker constants
; ============================================================
%define INFLIGHT_SIZE         512

; ============================================================
; SAR Scan mode
; ============================================================
%define SCAN_SAR                10

; ============================================================
; SAR defense class constants
; ============================================================
%define SAR_CLASS_NONE          0
%define SAR_CLASS_ACL           1
%define SAR_CLASS_STATEFUL      2
%define SAR_CLASS_DPI           3
%define SAR_CLASS_AI_EDR        4
%define SAR_CLASS_PROXY         5

; ============================================================
; SAR timing and behavior constants
; ============================================================
%define SAR_BASELINE_PROBES     5
%define SAR_PROBES_PER_PORT     3
%define SAR_SYNAPTIC_DEFAULT    1500
%define SAR_TREND_WINDOW        8
%define SAR_TIMEOUT_STREAK_MAX  3

; ============================================================
; KIS scan mode
; ============================================================
%define SCAN_KIS                11

; ============================================================
; KIS service fingerprint constants
; ============================================================
%define KIS_SVC_UNKNOWN         0
%define KIS_SVC_CLOSED          1
%define KIS_SVC_FILTERED        2
%define KIS_SVC_OPEN_RAW        3
%define KIS_SVC_HTTP            4
%define KIS_SVC_HTTPS           5
%define KIS_SVC_SSH             6
%define KIS_SVC_DNS             7
%define KIS_SVC_DB              8
%define KIS_SVC_HEAVY           9
%define KIS_SVC_VIRT            10

; ============================================================
; KIS thermal fuse trigger constants
; ============================================================
%define KIS_FUSE_TTL_SHIFT      1
%define KIS_FUSE_JITTER_EXP     2
%define KIS_FUSE_IMP_SPIKE      3
%define KIS_FUSE_TIMEOUTS       4
%define KIS_FUSE_DRIFT          5

; ============================================================
; KIS heat map symbols (ASCII)
; ============================================================
%define KIS_SYM_CLOSED     '.'
%define KIS_SYM_FILTERED   ':'
%define KIS_SYM_OPEN_L     'o'
%define KIS_SYM_OPEN_M     'O'
%define KIS_SYM_OPEN_H     '@'
%define KIS_SYM_VIRT       '#'
%define KIS_SYM_UNKNOWN    '?'

; ============================================================
; KIS probe and fuse tuning
; ============================================================
%define KIS_AMBIENT_PROBES       8
%define KIS_PROBES_PER_PORT      5
%define KIS_TTL_RECHECK_INTERVAL 32
%define KIS_TIMEOUT_STREAK_MAX   5
%define KIS_JITTER_THRESHOLD     110
%define KIS_IMP_SPIKE_MULT       5
%define KIS_DRIFT_THRESHOLD      115

; ============================================================
; Phantom scan mode
; ============================================================
%define SCAN_PHANTOM              12

; ============================================================
; Phantom port state constants
; ============================================================
%define PHANTOM_STATE_PASSIVE     0
%define PHANTOM_STATE_OPEN        1
%define PHANTOM_STATE_CLOSED      2
%define PHANTOM_STATE_FILTERED    3

; ============================================================
; Phantom tuning constants
; ============================================================
%define PHANTOM_LISTEN_SECS       10
%define PHANTOM_TEV_THRESHOLD     15
%define PHANTOM_OPEN_RATIO        150
%define PHANTOM_AMBIENT_PROBES    3
%define PHANTOM_BURST_WINDOW_NS   5000000
%define PHANTOM_JITTER_MIN_US     500
%define PHANTOM_JITTER_MAX_US     2500
%define PHANTOM_TIMEOUT_MS        1000
%define PHANTOM_TEV_STREAK_MAX    3
%define PHANTOM_TCP_FLAGS_ACK     0x10
%define PHANTOM_TCP_WINDOW        0

; ============================================================
; Callback scan mode
; ============================================================
%define SCAN_CALLBACK           13

; ============================================================
; Callback bait protocol constants
; ============================================================
%define CB_PROTO_DNS            1
%define CB_PROTO_NTP            2
%define CB_PROTO_ICMP           3
%define CB_PROTO_TCP_ACK        4

; ============================================================
; Callback response classification constants
; ============================================================
%define CB_CLASS_UNKNOWN        0
%define CB_CLASS_SILENT         1
%define CB_CLASS_STANDARD       2
%define CB_CLASS_RESPONSIVE     3
%define CB_CLASS_DELAYED        4

; ============================================================
; Callback tuning constants
; ============================================================
%define CB_RESPONSE_TIMEOUT_MS  500
%define CB_QUEUE_SIZE           16
%define CB_DELAYED_THRESHOLD_MS 200
%define CB_DNS_PORT_BE          0x3500
%define CB_NTP_PORT_BE          0x7B00
%define CB_IDENT                0xCB4B

; ============================================================
; Stateless cookie
; ============================================================
%define COOKIE_ENABLED    1

; ============================================================
; CIDR range iteration
; ============================================================
%define MAX_IP_RANGES     128
%define IP_RANGE_ENTRY    8

; ============================================================
; Resume/pause
; ============================================================
%define RESUME_FILE_NAME  "netrox-asm.resume", 0
%define SYS_SIGNAL        48
%define SIGINT            2

; ============================================================
; Additional scan modes (nmap parity)
; ============================================================
%define SCAN_CONNECT            14
%define SCAN_IDLE               15
%define SCAN_IPROTO             16
%define SCAN_PINGSWEEP          17
%define SCAN_LIST               18
%define SCAN_RPC                19
%define SCAN_SCTP_INIT          20
%define SCAN_SCTP_ECHO          21
%define SCAN_FTP_BOUNCE         22
%define SCAN_SCRIPT             23
%define SCAN_AGGRESSIVE         24
%define SCAN_SEQ                25
%define SCAN_ICMP_TS            26
%define SCAN_ICMP_NM            27
%define SCAN_ARP                28

; ============================================================
; SCTP constants
; ============================================================
%define SCTP_PROTO              132
%define SCTP_CHUNK_INIT         1
%define SCTP_CHUNK_COOKIE_ECHO  10

%endif
