//Strict TX/RX separation with a lock-free ring so TX never waits on RX
//Lock-free single-producer single-consumer ring buffer (result ring)
//SCAN_NETBIOS = 29
//XML, binary, and list output formats
//PACKET_TX_RING bypasses per-packet syscall overhead (sendto path)
#pragma once
#include "netrox-asc_abh.h"
#include <stdint.h>
#include <stdatomic.h>

#define RESULT_RING_SIZE 4096
#define ERROR_RING_SIZE  512

struct ResultRing {
    PortResult        slots[RESULT_RING_SIZE];
    volatile uint32_t head;
    uint8_t           _pad0[60];
    volatile uint32_t tail;
    uint8_t           _pad1[60];
};

inline bool ring_push(ResultRing* r, const PortResult* p) {
    uint32_t h = r->head;
    uint32_t next = (h + 1) & (RESULT_RING_SIZE - 1);
    if (next == r->tail) return false;
    r->slots[h] = *p;
    __atomic_store_n(&r->head, next, __ATOMIC_RELEASE);
    return true;
}

inline bool ring_pop(ResultRing* r, PortResult* out) {
    uint32_t t = r->tail;
    if (t == r->head) return false;
    *out = r->slots[t];
    __atomic_store_n(&r->tail, (t + 1) & (RESULT_RING_SIZE - 1), __ATOMIC_RELEASE);
    return true;
}

struct ErrorEntry {
    uint8_t  type;
    uint32_t ip;
    uint16_t port;
    int32_t  err;
};

struct ErrorRing {
    ErrorEntry        slots[ERROR_RING_SIZE];
    volatile uint32_t head;
    uint8_t           _pad0[60];
    volatile uint32_t tail;
    uint8_t           _pad1[60];
};

extern ResultRing g_result_ring;
extern ErrorRing  g_error_ring;



