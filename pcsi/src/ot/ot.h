#pragma once

#ifndef _OT_H
#define _OT_H

#include <cinttypes>
#include <string>
#include <vector>

// Network headers
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

// OT headers
#include "libOTe/Base/BaseOT.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"

// other
#include "common/pcsi_context.h"
#include "common/constants.h"

namespace PCSI {

std::vector<uint64_t> oprf_receiver(const std::vector<uint64_t>& in, PCSI::PCSIContext& context);

std::vector<std::vector<uint64_t>> oprf_sender(const std::vector<std::vector<uint64_t>>& in, PCSI::PCSIContext& context);

void ot_send(std::vector<std::vector<osuCrypto::block>>& msg, PCSI::PCSIContext& context);

void ot_recv(osuCrypto::BitVector& choices, std::vector<osuCrypto::block>& recv_msg, PCSI::PCSIContext& context);

void rot_send(std::vector<std::array<osuCrypto::block,2>> &msg, PCSI::PCSIContext& context);

void rot_recv(osuCrypto::BitVector& choices, std::vector<osuCrypto::block>& recv_msg, PCSI::PCSIContext& context);

}


#endif
