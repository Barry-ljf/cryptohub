#include "test/rsoprf_tests.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "psi/vole/oprf/rsopprf.h"
#include "psi/vole/oprf/rsoprf.h"

// #include "volePSI/RsOprf.h"
// #include "volePSI/RsOpprf.h"
#include <iomanip>

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "network/mem_channel.h"

// using coproto::LocalAsyncSocket;

using primihub::link::Channel;
using primihub::link::MemoryChannel;
using ChannelRole = MemoryChannel::ChannelRole;
using namespace oc;
namespace primihub::crypto {

// void RsOprf_eval_test() {
TEST(RsOprfTest, RsOprfEval) {
  using Channel = primihub::link::Channel;
  RsOprfSender sender;
  RsOprfReceiver recver;

  // auto sockets = LocalAsyncSocket::makePair();
  u64 n = 4000;
  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  std::vector<block> vals(n), recvOut(n);

  prng0.get(vals.data(), n);

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "RsOprfEval");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "RsOprfEval");

  auto p0_send = [&sender, &n, &prng0, &channel1]() {
    sender.send(n, prng0, channel1);
  };
  auto p1_recv = [&recver, &vals, &recvOut, &prng1, &channel2]() {
    recver.receive(vals, recvOut, prng1, channel2);
  };
  // auto p0 = sender.send(n, prng0, sockets[0]);
  // auto p1 = recver.receive(vals, recvOut, prng1, sockets[1]);

  auto p0_task = std::async(p0_send);
  auto p1_task = std::async(p1_recv);

  p0_task.get();
  p1_task.get();

  std::vector<block> vv(n);
  sender.eval(vals, vv);

  u64 count = 0;
  for (u64 i = 0; i < n; ++i) {
    auto v = sender.eval(vals[i]);
    if (recvOut[i] != v || recvOut[i] != vv[i]) {
      if (count < 10)
        std::cout << i << " " << recvOut[i] << " " << v << " " << vv[i]
                  << std::endl;
      else
        break;

      ++count;
    }
  }
  if (count) throw RTE_LOC;
}

// void RsOprf_mal_test() {
TEST(RsOprfTest, RsOprfMal) {
  using Channel = primihub::link::Channel;
  RsOprfSender sender;
  RsOprfReceiver recver;

  // auto sockets = LocalAsyncSocket::makePair();

  u64 n = 4000;
  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  std::vector<block> vals(n), recvOut(n);

  prng0.get(vals.data(), n);

  sender.mMalicious = true;
  recver.mMalicious = true;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "RsOprfMal");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "RsOprfMal");

  auto p0_send = [&sender, &n, &prng0, &channel1]() {
    sender.send(n, prng0, channel1);
  };
  auto p1_recv = [&recver, &vals, &recvOut, &prng1, &channel2]() {
    recver.receive(vals, recvOut, prng1, channel2);
  };

  auto p0_task = std::async(p0_send);
  auto p1_task = std::async(p1_recv);

  p0_task.get();
  p1_task.get();
  // auto p0 = sender.send(n, prng0, sockets[0]);
  // auto p1 = recver.receive(vals, recvOut, prng1, sockets[1]);

  // eval(p0, p1);

  std::vector<block> vv(n);
  sender.eval(vals, vv);

  u64 count = 0;
  for (u64 i = 0; i < n; ++i) {
    auto v = sender.eval(vals[i]);
    if (recvOut[i] != v || recvOut[i] != vv[i]) {
      if (count < 10)
        std::cout << i << " " << recvOut[i] << " " << v << " " << vv[i]
                  << std::endl;
      else
        break;

      ++count;
    }
  }
  if (count) throw RTE_LOC;
}

// void RsOprf_reduced_test() {
TEST(RsOprfTest, RsOprfReduced) {
  using Channel = primihub::link::Channel;
  RsOprfSender sender;
  RsOprfReceiver recver;

  // auto sockets = LocalAsyncSocket::makePair();

  u64 n = 4000;
  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  std::vector<block> vals(n), recvOut(n);

  prng0.get(vals.data(), n);

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "RsOprfReduced");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "RsOprfReduced");

  auto p0_send = [&sender, &n, &prng0, &channel1]() {
    sender.send(n, prng0, channel1);
  };
  auto p1_recv = [&recver, &vals, &recvOut, &prng1, &channel2]() {
    recver.receive(vals, recvOut, prng1, channel2);
  };

  auto p0_task = std::async(p0_send);
  auto p1_task = std::async(p1_recv);

  p0_task.get();
  p1_task.get();

  // auto p0 = sender.send(n, prng0, sockets[0], 0, true);
  // auto p1 = recver.receive(vals, recvOut, prng1, sockets[1], 0, true);

  // eval(p0, p1);

  std::vector<block> vv(n);
  sender.eval(vals, vv);

  u64 count = 0;
  for (u64 i = 0; i < n; ++i) {
    auto v = sender.eval(vals[i]);
    if (recvOut[i] != v || recvOut[i] != vv[i]) {
      if (count < 10)
        std::cout << i << " " << recvOut[i] << " " << v << " " << vv[i]
                  << std::endl;
      else
        break;

      ++count;
    }
  }
  if (count) throw RTE_LOC;
}
}  // namespace primihub::crypto
