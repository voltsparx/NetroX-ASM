
#include "args.h"
#include "color.h"
#include "output.h"
#include "targets.h"
#include "config.h"
#include "wizard.h"
#include "ring.h"
#include "kb.h"
#include "filter.h"

#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
static void short_yield() { Sleep(1); }
#else
#include <time.h>
static void short_yield() {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000; // 1ms
    nanosleep(&ts, nullptr);
}
#endif

static int g_open = 0;
static int g_filtered = 0;
static int g_closed = 0;
static uint64_t g_pps = 0;
ResultRing g_result_ring = {};
ErrorRing  g_error_ring = {};

static void cpp_on_port_result(const PortResult* r) {
    if (!r) return;
    if (g_filter_active && !filter_match(g_filter, r)) return;
    if (r->state == 1) g_open++;
    else if (r->state == 2) g_filtered++;
    else g_closed++;
    if (get_silent_mode()) {
        out_uint(g_current_ip);
        out_char(':');
        out_uint(r->port);
        out_char('
');
        return;
    }
    write_result(*r, !get_no_color());
}

static void cpp_on_host_up(uint32_t) {
    // verbosity handling can be added here
}

static void cpp_on_scan_done(void) {
    buf_flush();
}

int main(int argc, char** argv) {
    ScanConfig cfg = {};
    cfg.scan_mode = SCAN_SYN;
    if (!parse_args(argc, argv, cfg)) return 1;
    if (cfg.bandwidth_bps > 0) {
        cfg.rate_pps = (uint32_t)(cfg.bandwidth_bps / 592ULL);
    }
    if (cfg.cooldown_secs == 0) cfg.cooldown_secs = 8;

    ColorGuard::init();
    if (get_no_color()) ColorGuard::disable();

    if (get_help_mode()) { print_help(); return 0; }
    if (get_version_mode()) { out_str("NetroX-ASC v1.0.0\n"); buf_flush(); return 0; }
    if (get_about_mode()) { print_about(); buf_flush(); return 0; }
    if (get_echo_mode()) { print_echo_config(cfg); buf_flush(); return 0; }

    if (cfg.readscan_mode && cfg.readscan_path) {
        binary_readscan(cfg.readscan_path, cfg);
        buf_flush();
        return 0;
    }

    if (get_wizard_mode()) {
        cfg = run_wizard();
    }

    if (!get_silent_mode()) print_banner();

    TargetList targets;
    if (const char* iL = get_iL_path()) {
        targets.load_file(iL);
    } else if (cfg.target_ip) {
        targets.add(cfg.target_ip);
    }
    if (uint32_t rcount = get_random_count()) {
        targets.add_random(rcount);
    }
    size_t excl_count = 0;
    const uint32_t* excl = get_exclude_list(excl_count);
    targets.apply_excludes(excl, excl_count);
    if (!cfg.sequential_mode) targets.shuffle();

    cfg.on_port_result = cpp_on_port_result;
    cfg.on_host_up = cpp_on_host_up;
    cfg.on_scan_done = cpp_on_scan_done;

    extern void* asm_result_ring_ptr;
    extern void* asm_error_ring_ptr;

    for (size_t i = 0; i < targets.count; ++i) {
        cfg.target_ip = targets.ips[i];
        g_current_ip = cfg.target_ip;
        if (asm_scan_init(&cfg) != 0) continue;
        asm_get_local_ip(&cfg);

        if (cfg.tx_rx_split) {
            asm_result_ring_ptr = &g_result_ring;
            asm_error_ring_ptr = &g_error_ring;

            intptr_t rx_tid = (intptr_t)asm_start_rx_thread(&cfg);
            intptr_t tx_tid = (intptr_t)asm_start_tx_thread(&cfg);

            // Drain until scan index reaches end and ring is empty
            uint64_t idle = 0;
            while (true) {
                int drained = asm_drain_results(&cfg);
                uint64_t cur = asm_get_scan_index();
                if (cfg.index_end > 0 && cur >= cfg.index_end && drained == 0) {
                    if (++idle > 1000) break;
                } else {
                    idle = 0;
                }
                short_yield();
            }

#ifdef _WIN32
            if (tx_tid) {
                WaitForSingleObject((HANDLE)tx_tid, INFINITE);
                CloseHandle((HANDLE)tx_tid);
            }
            if (rx_tid) {
                WaitForSingleObject((HANDLE)rx_tid, INFINITE);
                CloseHandle((HANDLE)rx_tid);
            }
#endif
        } else {
            asm_scan_run(&cfg);
        }

        asm_scan_cleanup();
    }

    if (!get_silent_mode()) print_summary(cfg, g_open, g_filtered, g_closed, 0);
    buf_flush();
    return 0;
}
