#pragma once
#include <stdint.h>
#include "netrox-asc_abh.h"

struct HostKB {
    uint32_t ip;
    uint8_t  valid;
    PortResult ports[512];
    uint16_t port_count;
    char hostname[256];
    uint8_t mac[6];
    char mac_vendor[32];
    char netbios_name[32];
    char os_guess[64];
    uint8_t os_confidence;
    bool heartbleed_found;
    uint8_t tls_versions_seen;
};

class KnowledgeBase {
public:
    void record(const PortResult& r);
    void record_hostname(uint32_t ip, const char* name);
    HostKB* get(uint32_t ip);
    void dump_all(int fd, uint8_t format);
private:
    HostKB table_[1024] = {};
};



