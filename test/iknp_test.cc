#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include "network/mem_channel.h"
#include "psi/ot/base/baseot.h"
#include "psi/ot/base/otextinterface.h"
#include "psi/ot/tools/tools.h"
#include "psi/ot/twochooseone/iknp/iknpotextreceiver.h"
#include "psi/ot/twochooseone/iknp/iknpotextsender.h"
#include "test/ot_tests.h"

using osuCrypto::BitVector;
using osuCrypto::block;
using osuCrypto::PRNG;
using primihub::crypto::IknpOtExtReceiver;
using primihub::crypto::IknpOtExtSender;
using primihub::crypto::OT_100Receive_Test;
using primihub::link::Channel;
using primihub::link::MemoryChannel;

TEST(iknp, ot_test) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "ot_test");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "ot_test");

  PRNG prng0(block(4253465, 3434565));
  PRNG prng1(block(42532335, 334565));

  u64 numOTs = 200;

  std::vector<block> recvMsg(numOTs), baseRecv(128);
  std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
  BitVector choices(numOTs), baseChoice(128);
  choices.randomize(prng0);
  baseChoice.randomize(prng0);

  prng0.get((u8 *)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
  for (u64 i = 0; i < 128; ++i) {
    baseRecv[i] = baseSend[i][baseChoice[i]];
  }

  IknpOtExtSender sender;
  IknpOtExtReceiver recv;

  recv.setBaseOts(baseSend);
  // auto proto0 = recv.receive(choices, recvMsg, prng0, sockets[0]);
  auto recv_fn = [&recv, &choices, &recvMsg, &prng0, channel1]() {
    recv.receive(choices, recvMsg, prng0, channel1);
  };

  auto fut1 = std::async(recv_fn);

  sender.setBaseOts(baseRecv, baseChoice);
  // auto proto1 = sender.send(sendMsg, prng1, sockets[1]);
  auto send_fn = [&sender, &sendMsg, &prng1, channel2]() {
    sender.send(sendMsg, prng1, channel2);
  };

  auto fut2 = std::async(send_fn);

  fut1.get();
  fut2.get();

  // eval(proto0, proto1);

  OT_100Receive_Test(choices, recvMsg, sendMsg);
}

TEST(iknp, dot_test) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "dot_test");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "dot_test");

  PRNG prng0(block(4253465, 3434565));
  PRNG prng1(block(42532335, 334565));

  u64 numTrials = 4;
  for (u64 t = 0; t < numTrials; ++t) {
    u64 numOTs = 4234;

    AlignedUnVector<block> recvMsg(numOTs), baseRecv(128);
    AlignedUnVector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
    BitVector choices(numOTs);
    choices.randomize(prng0);

    BitVector baseChoice(128);
    baseChoice.randomize(prng0);

    for (u64 i = 0; i < 128; ++i) {
      baseSend[i][0] = prng0.get<block>();
      baseSend[i][1] = prng0.get<block>();
      baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    IknpOtExtSender sender;
    IknpOtExtReceiver recv;

    sender.mHash = false;
    recv.mHash = false;

    recv.setBaseOts(baseSend);
    // auto proto0 = recv.receive(choices, recvMsg, prng0, sockets[0]);
    auto recv_fn = [&recv, &choices, &recvMsg, &prng0, channel1]() {
      recv.receive(choices, recvMsg, prng0, channel1);
    };

    auto fut1 = std::async(recv_fn);

    block delta = baseChoice.getArrayView<block>()[0];

    sender.setBaseOts(baseRecv, baseChoice);
    // auto proto1 = sender.send(sendMsg, prng1, sockets[1]);
    auto send_fn = [&sender, &sendMsg, &prng1, channel2]() {
      sender.send(sendMsg, prng1, channel2);
    };

    auto fut2 = std::async(send_fn);

    // eval(proto0, proto1);
    fut1.get();
    fut2.get();

    OT_100Receive_Test(choices, recvMsg, sendMsg);

    for (auto &s : sendMsg) {
      if (neq(s[0] ^ delta, s[1])) throw std::runtime_error(LOCATION);
    }
  }
}
