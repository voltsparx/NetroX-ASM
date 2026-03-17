#pragma once

#include <stdint.h>
#include "../../include/netrox-asc_abh.h"

bool save_resume(const ScanConfig& cfg, uint16_t last_port);
bool load_resume(ScanConfig& cfg, uint16_t& last_port);
bool load_config_file(const char* path, ScanConfig& cfg);



