#include "test/rspsi_tests.h"

#include <glog/logging.h>
#include <gtest/gtest.h> 
#include <time.h>
#include <iostream>

#include "psi/vole/psi/rspsi.h"
// #include "volePSI/RsCpsi.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "network/mem_channel.h"

using primihub::link::Channel;
using primihub::link::MemoryChannel;
using ChannelRole = MemoryChannel::ChannelRole;

using namespace oc;
namespace primihub::crypto {

std::vector<u64> run(PRNG& prng, std::vector<block>& recvSet,
                     std::vector<block>& sendSet, bool mal,
                     std::string taskname, u64 nt = 1, bool reduced = false) {
  RsPsiReceiver recver;
  RsPsiSender sender;

  recver.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);
  sender.init(sendSet.size(), recvSet.size(), 40, prng.get(), mal, nt, reduced);

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, taskname);

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, taskname);

  auto p0_recv = [&recver, &recvSet, &channel1]() {
    recver.run(recvSet, channel1);
  };
  auto p1_send = [&sender, &sendSet, &channel2]() {
    sender.run(sendSet, channel2);
  };

  auto p0_task = std::async(p0_recv);
  auto p1_task = std::async(p1_send);

  std::clock_t start = clock();
  p0_task.get();
  p1_task.get();
  std::clock_t end = clock();
  std::cout << taskname << "cost " << (double)(end - start) / CLOCKS_PER_SEC << "sec." << std::endl;

  return recver.mIntersection;
}

TEST(RsPsiTest, EmptyTest) {
  std::string taskname = "EmptyTest";

  // u64 n = cmd.getOr("n", 13243);
  u64 n = 1000000;

  std::vector<block> recvSet(n), sendSet(n);

  PRNG prng(ZeroBlock);

  prng.get(recvSet.data(), recvSet.size());
  prng.get(sendSet.data(), sendSet.size());

  auto inter = run(prng, recvSet, sendSet, false, taskname);

  if (inter.size()) throw RTE_LOC;
}

TEST(RsPsiTest, PartialTest) {
  std::string taskname = "PartialTest";
  // u64 n = cmd.getOr("n", 13243);
  u64 n = 1000000;
  std::vector<block> recvSet(n), sendSet(n);
  PRNG prng(ZeroBlock);
  prng.get(recvSet.data(), recvSet.size());
  prng.get(sendSet.data(), sendSet.size());

  std::set<u64> exp;
  for (u64 i = 0; i < n; ++i) {
    if (prng.getBit()) {
      recvSet[i] = sendSet[(i + 312) % n];
      exp.insert(i);
    }
  }

  auto inter = run(prng, recvSet, sendSet, false, taskname);
  std::set<u64> act(inter.begin(), inter.end());
  if (act != exp) {
    std::cout << "exp size " << exp.size() << std::endl;
    std::cout << "act size " << act.size() << std::endl;
    throw RTE_LOC;
  }
}

TEST(RsPsiTest, FullTest) {
  std::string taskname = "FullTest";
  // u64 n = cmd.getOr("n", 13243);
  u64 n = 1000000;
  std::vector<block> recvSet(n), sendSet(n);
  PRNG prng(ZeroBlock);
  prng.get(recvSet.data(), recvSet.size());
  sendSet = recvSet;

  std::set<u64> exp;
  for (u64 i = 0; i < n; ++i) exp.insert(i);

  auto inter = run(prng, recvSet, sendSet, false, taskname);
  std::set<u64> act(inter.begin(), inter.end());
  if (act != exp) throw RTE_LOC;
}

TEST(RsPsiTest, ReducedTest) {
  std::string taskname = "ReducedTest";
  // u64 n = cmd.getOr("n", 13243);
  u64 n = 1000000;
  std::vector<block> recvSet(n), sendSet(n);
  PRNG prng(ZeroBlock);
  prng.get(recvSet.data(), recvSet.size());
  sendSet = recvSet;

  std::set<u64> exp;
  for (u64 i = 0; i < n; ++i) exp.insert(i);

  auto inter = run(prng, recvSet, sendSet, false, taskname, 1, true);
  std::set<u64> act(inter.begin(), inter.end());
  if (act != exp) throw RTE_LOC;
}

TEST(RsPsiTest, MultiThrdTest) {
  std::string taskname = "MultiThrdTest";
  // u64 n = cmd.getOr("n", 13243);
  u64 n = 1000000;
  // u64 nt = cmd.getOr("nt", 8);
  u64 nt = 8;
  std::vector<block> recvSet(n), sendSet(n);
  PRNG prng(ZeroBlock);
  prng.get(recvSet.data(), recvSet.size());
  sendSet = recvSet;

  std::set<u64> exp;
  for (u64 i = 0; i < n; ++i) exp.insert(i);

  auto inter = run(prng, recvSet, sendSet, false, taskname, nt);
  std::set<u64> act(inter.begin(), inter.end());
  if (act != exp) throw RTE_LOC;
}

TEST(RsPsiTest, MalTest) {
  std::string taskname = "MalTest";
  // u64 n = cmd.getOr("n", 13243);
  u64 n = 1000000;
  std::vector<block> recvSet(n), sendSet(n);
  PRNG prng(ZeroBlock);
  prng.get(recvSet.data(), recvSet.size());
  prng.get(sendSet.data(), sendSet.size());

  std::set<u64> exp;
  for (u64 i = 0; i < n; ++i) {
    if (prng.getBit()) {
      recvSet[i] = sendSet[(i + 312) % n];
      exp.insert(i);
    }
  }

  auto inter = run(prng, recvSet, sendSet, true, taskname);
  std::set<u64> act(inter.begin(), inter.end());
  if (act != exp) throw RTE_LOC;
}

}  // namespace primihub::crypto