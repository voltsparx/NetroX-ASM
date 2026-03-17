#include "output.h"
#include <cstring>

static bool g_json_first = true;

extern void buf_flush();

void json_header(const ScanConfig& cfg) {
    g_json_first = true;
    out_str("{\"scanner\":\"netrox-asc\",\"target\":\"");
    out_uint(cfg.target_ip);
    out_str("\",\"ports\":[");
}

void json_port(const PortResult& r) {
    if (!g_json_first) out_str(",");
    g_json_first = false;
    out_str("{\"port\":");
    out_uint(r.port);
    out_str(",\"proto\":\"tcp\",\"state\":\"");
    out_str(r.state == 1 ? "open" : (r.state == 2 ? "filtered" : "closed"));
    out_str("\",\"service\":\"");
    out_str(r.service);
    out_str("\",\"version\":\"");
    out_str(r.version);
    out_str("\"}");
}

void json_footer(uint64_t elapsed_ms, int open_count, int filtered_count, int closed_count) {
    out_str("],\"summary\":{\"open\":");
    out_uint(open_count);
    out_str(",\"filtered\":");
    out_uint(filtered_count);
    out_str(",\"closed\":");
    out_uint(closed_count);
    out_str(",\"elapsed_ms\":");
    out_uint(elapsed_ms);
    out_str("}}\n");
    buf_flush();
}



