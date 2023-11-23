#include <glog/logging.h>
#include <gtest/gtest.h>

#include "network/mem_channel.h"
#include "psi/ot/tools/silentpprf.h"

using primihub::crypto::PprfOutputFormat;
using primihub::crypto::SilentMultiPprfReceiver;
using primihub::crypto::SilentMultiPprfSender;
using primihub::link::Channel;
using primihub::link::MemoryChannel;
using primihub::link::Status;
using ChannelRole = MemoryChannel::ChannelRole;

TEST(silentpprf, base_test) {
  u64 depth = 3;
  u64 domain = 1ull << depth;
  auto threads = 3;
  u64 numPoints = 8;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "base_test");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "base_test");

  PRNG prng(ZeroBlock);

  auto format = PprfOutputFormat::Plain;
  SilentMultiPprfSender sender;
  SilentMultiPprfReceiver recver;

  sender.configure(domain, numPoints);
  recver.configure(domain, numPoints);

  auto numOTs = sender.baseOtCount();
  std::vector<std::array<block, 2>> sendOTs(numOTs);
  std::vector<block> recvOTs(numOTs);
  BitVector recvBits = recver.sampleChoiceBits(domain, format, prng);

  prng.get(sendOTs.data(), sendOTs.size());
  // sendOTs[cmd.getOr("i",0)] = prng.get();

  // recvBits[16] = 1;
  for (u64 i = 0; i < numOTs; ++i) {
    // recvBits[i] = 0;
    recvOTs[i] = sendOTs[i][recvBits[i]];
  }
  sender.setBase(sendOTs);
  recver.setBase(recvOTs);

  Matrix<block> sOut(domain, numPoints);
  Matrix<block> rOut(domain, numPoints);
  std::vector<u64> points(numPoints);
  recver.getPoints(points, format);

  auto sender_fn = [channel1, &sender, &prng, &sOut, format, threads]() {
    sender.expand(channel1, {&CCBlock, 1}, prng, sOut, format, true, threads);
  };

  auto recver_fn = [channel2, &recver, &prng, &rOut, format, threads]() {
    recver.expand(channel2, prng, rOut, format, true, threads);
  };

  std::future<void> recver_fut = std::async(recver_fn);
  std::future<void> sender_fut = std::async(sender_fn);

  sender_fut.get();
  recver_fut.get();

  bool failed = false;

  for (u64 j = 0; j < numPoints; ++j) {
    for (u64 i = 0; i < domain; ++i) {
      auto exp = sOut(i, j);
      if (points[j] == i) exp = exp ^ CCBlock;

      if (neq(exp, rOut(i, j))) failed = true;
    }
  }

  EXPECT_EQ(failed == false, true);
}
