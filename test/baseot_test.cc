#include <glog/logging.h>
#include <gtest/gtest.h>

#include "network/mem_channel.h"
#include "psi/ot/base/simplestot.h"
#include <time.h>
#include <iostream>

using osuCrypto::block;
using primihub::crypto::SimplestOT;
using primihub::link::Channel;
using primihub::link::ChannelBase;
using primihub::link::MemoryChannel;
using primihub::link::Status;
using ChannelRole = MemoryChannel::ChannelRole;

TEST(baseot, simplestot_test) {
  std::clock_t start = clock();
  using Channel = primihub::link::Channel;
  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "simplestot_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "simplestot_test");
  
  PRNG prng0(block(4253465, 3434565));
  PRNG prng1(block(42532335, 334565));

  u64 numOTs = 50;
  std::vector<block> recvMsg(numOTs);
  std::vector<std::array<block, 2>> sendMsg(numOTs);
  BitVector choices(numOTs);
  choices.randomize(prng0);

  SimplestOT baseOTs;
  auto recv_fn = [&]() { baseOTs.receive(choices, recvMsg, prng0, channel1); };

  auto recv_fut = std::async(recv_fn);

  SimplestOT baseOTs0;
  auto send_fn = [&]() { baseOTs0.send(sendMsg, prng1, channel2); };

  auto send_fut = std::async(send_fn);
 
  recv_fut.get();
  send_fut.get();
  std::clock_t end = clock();
  std::cout << "simplestot_test" << "cost " << (double)(end - start) / CLOCKS_PER_SEC << "sec." << std::endl;

  for (u64 i = 0; i < numOTs; ++i) {
    if (neq(recvMsg[i], sendMsg[i][choices[i]])) {
      std::stringstream ss;
      ss << "failed " << i << " exp = m[" << int(choices[i])
         << "], act = " << recvMsg[i] << " true = " << sendMsg[i][0] << ", "
         << sendMsg[i][1];
      LOG(ERROR) << ss.str();
      throw std::runtime_error(ss.str());
    }
  }
}
