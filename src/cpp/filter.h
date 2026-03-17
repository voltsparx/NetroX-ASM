// Q1: TCP sequence number uses SipHash-2-4 over {src_ip,src_port,dst_ip,dst_port}.
// Q2: sendmmsg syscall number 307.
// Q3: Cooldown period is RX-after-TX; default is 8 seconds.
// Q4: Modbus/TCP 502, Siemens S7 102, BACnet/IP 47808.
// Q5: RX thread pushes duplicates before result_map dedup; dedup must happen before ring push.
#pragma once

#include "netrox-asc_abh.h"
#include <stdint.h>

struct FilterExpr;

FilterExpr* filter_parse(const char* s);
bool filter_match(const FilterExpr* f, const PortResult* r);
void filter_free(FilterExpr* f);
