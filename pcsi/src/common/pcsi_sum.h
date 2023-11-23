#pragma once

#ifndef _PCSI_SUM_H
#define _PCSI_SUM_H


#include "abycore/aby/abyparty.h"
#include "abycore/circuit/share.h"
// #include "utils.h"
#include "pcsi_context.h"

#include "libOTe/Base/BaseOT.h"

namespace PCSI {

static std::vector<uint64_t> DEFAULT_VECTOR;

uint64_t exec(const std::vector<uint64_t>& inputs, PCSIContext& ctx, const std::vector<uint64_t>& data = DEFAULT_VECTOR);

}


#endif
