#include "kb.h"
#include <cstring>

static inline uint32_t kb_hash(uint32_t ip) { return ip & 1023u; }

HostKB* KnowledgeBase::get(uint32_t ip) {
    uint32_t idx = kb_hash(ip);
    HostKB* h = &table_[idx];
    if (h->valid && h->ip == ip) return h;
    return nullptr;
}

void KnowledgeBase::record(const PortResult& r) {
    uint32_t idx = kb_hash(r.port); // fallback if no ip; caller should set ip
    HostKB* h = &table_[idx];
    if (!h->valid) { h->valid = 1; h->ip = 0; h->port_count = 0; }
    if (h->port_count < 512) {
        h->ports[h->port_count++] = r;
    }
}

void KnowledgeBase::record_hostname(uint32_t ip, const char* name) {
    uint32_t idx = kb_hash(ip);
    HostKB* h = &table_[idx];
    if (!h->valid || h->ip != ip) { h->valid = 1; h->ip = ip; h->port_count = 0; }
    if (name) {
        std::strncpy(h->hostname, name, sizeof(h->hostname) - 1);
        h->hostname[sizeof(h->hostname) - 1] = 0;
    }
}

void KnowledgeBase::dump_all(int, uint8_t) {
    // stub: integrate with output formats later
}
