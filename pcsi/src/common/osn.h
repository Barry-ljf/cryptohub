#pragma once

#include <vector>

#include "libOTe/Base/BaseOT.h"


void initialize(int values, int levels);

void route(int n, int cue_level, int index, const std::vector<int> &src, const std::vector<int> &dest);

void masked_eval (int n, int cur_level, int index, std::vector<uint64_t> &src, std::vector<std::vector<osuCrypto::block>> &ot_output);

osuCrypto::BitVector retrieve_switches(int values);