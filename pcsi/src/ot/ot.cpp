#include "ot.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include "libOTe/Base/BaseOT.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"

#include "common/constants.h"
#include "common/pcsi_context.h"

#include <thread>
#include <bits/stdc++.h>

using namespace osuCrypto;

namespace PCSI {

std::vector<uint64_t> oprf_receiver(const std::vector<uint64_t>& in, PCSI::PCSIContext& context) {
    std::vector<uint64_t> out;
    out.reserve(in.size());

    // initial parameters
    uint32_t ot_num = in.size();
    PRNG prng(_mm_set_epi32(0, 0, 0, 0));
    KkrtNcoOtReceiver recv;
    recv.configure(false, 40, sec_para);

    // configure network
    std::string name = "pcsi";
    IOService ios;
    Session ep(ios, context.ip, context.port + 600, SessionMode::Client, name);
    auto recv_chl = ep.addChannel(name, name);

    uint64_t base_ot_num = recv.getBaseOTCount();
    std::vector<std::array<osuCrypto::block, 2>> base_send(base_ot_num);

    DefaultBaseOT base_ot;
    base_ot.send(base_send, prng, recv_chl, 1);
    recv.setBaseOts(base_send);

    // oprf
    recv.init(ot_num, prng, recv_chl);
    std::vector<osuCrypto::block> blocks(ot_num), receiver_encoding(ot_num);

    for (auto i = 0ull; i < in.size(); i++) {
        blocks[i] = osuCrypto::toBlock(in[i]);
    }

    for (auto i = 0ull; i < ot_num && i < in.size(); i++) {
        recv.encode(i, &blocks[i], reinterpret_cast<uint8_t *>(&receiver_encoding[i]), sizeof(osuCrypto::block));
    }


    recv.sendCorrection(recv_chl, ot_num);

    for (auto i = 0ull; i < ot_num; i++) {
        out.push_back(reinterpret_cast<uint64_t *>(&receiver_encoding.at(i))[0] &= _61_mask);
    }

    recv_chl.close();
    ep.stop();
    ios.stop();

    return out;
}

std::vector<std::vector<uint64_t>> oprf_sender(const std::vector<std::vector<uint64_t>>& in, PCSI::PCSIContext& context) {
    std::vector<std::vector<uint64_t>> out(in.size());
    
    uint32_t ot_num = in.size();
    PRNG prng(_mm_set_epi32(0, 0, 0, 1));
    KkrtNcoOtSender sender;
    sender.configure(false, 40, sec_para);

    std::string name = "pcsi";
    IOService ios;
    Session ep(ios, context.ip, context.port + 600, SessionMode::Server, name);
    auto send_chl = ep.addChannel(name, name);

    uint64_t base_ot_num = sender.getBaseOTCount();
    DefaultBaseOT base_ot;
    BitVector choices(base_ot_num); // sender's random s 
    std::vector<osuCrypto::block> base_recv(base_ot_num);
    choices.randomize(prng);

    base_ot.receive(choices, base_recv, prng, send_chl, 1);

    sender.setBaseOts(base_recv, choices);

    sender.init(ot_num, prng, send_chl);

    std::vector<std::vector<osuCrypto::block>> in_blocks(ot_num), out_blocks(ot_num);

    // convert inputs' data structure into osuCrypto::block
    for (auto i = 0ull; i < ot_num; i++) {
        out_blocks[i].resize(in[i].size());
        for (auto &msg : in[i]) {
            in_blocks[i].push_back(osuCrypto::toBlock(msg));
        }
    }

    sender.recvCorrection(send_chl, ot_num);

    for (auto i = 0ull; i < ot_num; i++) {
        for (auto j = 0ull; j < in_blocks.at(i).size(); j++) {
            sender.encode(i, &in_blocks.at(i).at(j), &out_blocks.at(i).at(j), sizeof(osuCrypto::block));
        }
    }

    for (auto i = 0ull; i < ot_num; i++) {
        for (auto &encoding: out_blocks.at(i)) {
            out[i].push_back(reinterpret_cast<uint64_t *>(&encoding)[0] &= _61_mask);
        }
    }


    send_chl.close();
    ep.stop();
    ios.stop();

    return out;
}

void ot_send(std::vector<std::vector<osuCrypto::block>>& msg, PCSI::PCSIContext& context) {
    osuCrypto::IOService ios;
    std::string name = "pcsi";
    osuCrypto::Session ep(ios, context.ip, context.port + 1, SessionMode::Client, name);
    auto send_chl = ep.addChannel(name, name);

    PRNG prng(_mm_set_epi32(0, 0, 0, 0));

    std::vector<osuCrypto::block> base_recv(sec_para);
    DefaultBaseOT base_ot;
    BitVector base_choices(sec_para);
    base_choices.randomize(prng);

    // start ot extension
    osuCrypto::IknpOtExtSender sender;
    base_ot.receive(base_choices, base_recv, prng, send_chl, 1);
    sender.setBaseOts(base_recv, base_choices);

    std::vector<std::array<osuCrypto::block, 2>> send_msg(msg.size());

    sender.send(send_msg, prng, send_chl);

    for (auto i = 0ull; i < send_msg.size(); i++) {
        send_msg[i][0] ^= msg[i][0];
        send_msg[i][1] ^= msg[i][1];
        send_chl.send(std::move(send_msg[i]));
    }

}

void ot_recv(osuCrypto::BitVector& choices, std::vector<osuCrypto::block>& recv_msg, PCSI::PCSIContext& context) {
    osuCrypto::IOService ios;
    std::string name = "pcsi";
    osuCrypto::Session ep(ios, context.ip, context.port + 1, SessionMode::Server, name);
    auto recv_chl = ep.addChannel(name, name);

    PRNG prng(_mm_set_epi32(0, 0, 0, 1));

    uint64_t ot_num = choices.size();
    std::vector<std::array<osuCrypto::block, 2>> base_send(sec_para);

    prng.get((uint8_t*)base_send.data()->data(), sizeof(osuCrypto::block) * 2 * base_send.size());

    // start ot extension 
    DefaultBaseOT base_ot;
    base_ot.send(base_send, prng, recv_chl, 1);

    osuCrypto::IknpOtExtReceiver recv;
    recv.setBaseOts(base_send); 
    recv.receive(choices, recv_msg, prng, recv_chl);

    std::vector<std::array<osuCrypto::block, 2>> correction(ot_num);

    auto bit = choices.begin();

    for (auto i = 0ull; i < choices.size(); i++) {
        recv_chl.recv(correction[i].data(), 2);
        recv_msg[i] ^= correction[i][*bit];
        bit++;
    }
}

void rot_send(std::vector<std::array<osuCrypto::block,2>> &msg, PCSI::PCSIContext& context) {
    osuCrypto::IOService ios;
    std::string name = "pcsi";
    osuCrypto::Session ep(ios, context.ip, context.port + 1, SessionMode::Client, name);
    auto send_chl = ep.addChannel(name, name);

    PRNG prng(_mm_set_epi32(0, 0, 0, 0));
    std::vector<osuCrypto::block> base_recv(sec_para);  // 128
    DefaultBaseOT base_ot;
    BitVector base_choices(sec_para);
    base_choices.randomize(prng);
    // start ot extension
    osuCrypto::IknpOtExtSender sender;
    base_ot.receive(base_choices, base_recv, prng, send_chl, 1);
    sender.setBaseOts(base_recv, base_choices);
    sender.send(msg, prng, send_chl);
}

void rot_recv(osuCrypto::BitVector& choices, std::vector<osuCrypto::block>& recv_msg, PCSI::PCSIContext& context) {
    osuCrypto::IOService ios;
    std::string name = "pcsi";
    osuCrypto::Session ep(ios, context.ip, context.port + 1, SessionMode::Server, name);
    auto recv_chl = ep.addChannel(name, name);

    PRNG prng(_mm_set_epi32(0, 0, 0, 1));
    uint64_t ot_num = choices.size();

    std::vector<std::array<osuCrypto::block, 2>> base_send(sec_para);

    prng.get((uint8_t*)base_send.data()->data(), sizeof(osuCrypto::block) * 2 * base_send.size());

    DefaultBaseOT base_ot;
    base_ot.send(base_send, prng, recv_chl, 1);

    // start ot extension
    osuCrypto::IknpOtExtReceiver recv;
    recv.setBaseOts(base_send);
    recv.receive(choices, recv_msg, prng, recv_chl);
}

}
