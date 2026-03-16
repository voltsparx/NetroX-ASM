#include "args.h"
#include "color.h"
#include "output.h"
#include "targets.h"
#include "config.h"
#include "wizard.h"

#include <cstring>
#include <cstdlib>

static int g_open = 0;
static int g_filtered = 0;
static int g_closed = 0;
static uint64_t g_pps = 0;

static void cpp_on_port_result(const PortResult* r) {
    if (!r) return;
    if (r->state == 1) g_open++;
    else if (r->state == 2) g_filtered++;
    else g_closed++;
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

    ColorGuard::init();
    if (get_no_color()) ColorGuard::disable();

    if (get_help_mode()) { print_help(); return 0; }
    if (get_version_mode()) { out_str("NetroX-ASC v1.0.0\n"); buf_flush(); return 0; }
    if (get_about_mode()) { print_about(); buf_flush(); return 0; }
    if (get_echo_mode()) { print_echo_config(cfg); buf_flush(); return 0; }

    if (get_wizard_mode()) {
        cfg = run_wizard();
    }

    print_banner();

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

    for (size_t i = 0; i < targets.count; ++i) {
        cfg.target_ip = targets.ips[i];
        if (asm_scan_init(&cfg) != 0) continue;
        asm_get_local_ip(&cfg);
        asm_scan_run(&cfg);
        asm_scan_cleanup();
    }

    print_summary(cfg, g_open, g_filtered, g_closed, 0);
    buf_flush();
    return 0;
}

