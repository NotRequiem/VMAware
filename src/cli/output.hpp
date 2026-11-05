#pragma once

#include "types.hpp"

#include <string>

bool is_admin() noexcept;
const char* color(const u8 score);
const char* get_version();
const char* get_date();
void console_pause();
bool is_vm_brand_multiple(const std::string& vm_brand) noexcept;
const char* get_vm_description(const std::string& vm_brand);

bool parse_disable_token(const char* token);
void generate_json(const char* output);
u32 get_technique_count() noexcept;

i32 run_stdout(bool high_threshold, bool all, bool dynamic) noexcept;
u32 run_percent(bool high_threshold, bool all, bool dynamic) noexcept;
bool run_detect(bool high_threshold, bool all, bool dynamic) noexcept;
std::string run_brand(bool high_threshold, bool all, bool dynamic);
std::string run_type(bool high_threshold, bool all, bool dynamic);
std::string run_conclusion(bool high_threshold, bool all, bool dynamic);

void general(bool high_threshold, bool all, bool dynamic, const char* output_file = nullptr);
