#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include "network/mem_channel.h"
#include "psi/ot/vole/noisy/noisyvolereceiver.h"
#include "psi/ot/vole/noisy/noisyvolesender.h"
#include "psi/ot/vole/silent/silentvolereceiver.h"
#include "psi/ot/vole/silent/silentvolesender.h"

using osuCrypto::block;
using osuCrypto::PRNG;
using osuCrypto::Timer;
using primihub::crypto::MultType;
using primihub::crypto::NoisyVoleReceiver;
using primihub::crypto::NoisyVoleSender;
using primihub::crypto::SilentBaseType;
using primihub::crypto::SilentSecType;
using primihub::crypto::SilentVoleReceiver;
using primihub::crypto::SilentVoleSender;
using primihub::link::Channel;
using primihub::link::MemoryChannel;
using ChannelRole = primihub::link::MemoryChannel::ChannelRole;

namespace {
void fakeBase(u64 n, u64 threads, PRNG &prng, block delta,
              SilentVoleReceiver &recver, SilentVoleSender &sender) {
  sender.configure(n, SilentBaseType::Base, 128);
  recver.configure(n, SilentBaseType::Base, 128);

  std::vector<std::array<block, 2>> msg2(sender.silentBaseOtCount());
  BitVector choices = recver.sampleBaseChoiceBits(prng);
  std::vector<block> msg(choices.size());

  if (choices.size() != msg2.size()) throw RTE_LOC;

  for (auto &m : msg2) {
    m[0] = prng.get();
    m[1] = prng.get();
  }

  for (auto i : rng(msg.size())) msg[i] = msg2[i][choices[i]];

  auto y = recver.sampleBaseVoleVals(prng);
  ;
  std::vector<block> c(y.size()), b(y.size());
  prng.get(c.data(), c.size());
  for (auto i : rng(y.size())) {
    b[i] = delta.gf128Mul(y[i]) ^ c[i];
  }
  sender.setSilentBaseOts(msg2, b);

  // fake base OTs.
  recver.setSilentBaseOts(msg, c);
}
}  // namespace

TEST(vole, noisyvole) {
  using Channel = primihub::link::Channel;

  Timer timer;
  timer.setTimePoint("start");
  u64 n = 123;
  block seed = block(100, 89);
  PRNG prng(seed);

  block x = prng.get();
  std::vector<block> y(n), z0(n), z1(n);
  prng.get<block>(y);

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "noisyvole");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "noisyvole");

  NoisyVoleReceiver recv;
  NoisyVoleSender send;

  recv.setTimer(timer);
  send.setTimer(timer);

  timer.setTimePoint("net");

  BitVector recvChoice((u8 *)&x, 128);
  std::vector<block> otRecvMsg(128);
  std::vector<std::array<block, 2>> otSendMsg(128);
  prng.get<std::array<block, 2>>(otSendMsg);
  for (u64 i = 0; i < 128; ++i) otRecvMsg[i] = otSendMsg[i][recvChoice[i]];
  timer.setTimePoint("ot");

  // auto p0 = recv.receive(y, z0, prng, otSendMsg, chls[0]);
  // auto p1 = send.send(x, z1, prng, otRecvMsg, chls[1]);

  // eval(p0, p1);
  auto send_fn = [&send, &x, &z1, &prng, &otRecvMsg, channel1]() {
    send.send(x, z1, prng, otRecvMsg, channel1);
  };

  auto recv_fn = [&recv, &y, &z0, &prng, &otSendMsg, channel2]() {
    recv.receive(y, z0, prng, otSendMsg, channel2);
  };

  auto fut1 = std::async(send_fn);
  auto fut2 = std::async(recv_fn);

  fut1.get();
  fut2.get();

  for (u64 i = 0; i < n; ++i) {
    if (y[i].gf128Mul(x) != (z0[i] ^ z1[i])) {
      throw RTE_LOC;
    }
  }
  timer.setTimePoint("done");
}

TEST(vole, round_test) {
  using Channel = primihub::link::Channel;

  // cp::BufferingSocket chls[2];
  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "round_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "round_test");

  Timer timer;
  timer.setTimePoint("start");
  u64 n = 12343;
  block seed = block(0, 0);
  PRNG prng(seed);

  block x = prng.get();

  SilentVoleReceiver recv;
  SilentVoleSender send;

  send.mMalType = SilentSecType::SemiHonest;
  recv.mMalType = SilentSecType::SemiHonest;
  for (u64 jj : {0, 1}) {
    send.configure(n, SilentBaseType::Base);
    recv.configure(n, SilentBaseType::Base);
    // c * x = z + m

    // for (u64 n = 5000; n < 10000; ++n)
    {
      recv.setTimer(timer);
      send.setTimer(timer);
      if (jj) {
        std::vector<block> c(n), z0(n), z1(n);
        // auto p0 = recv.silentReceive(c, z0, prng, client_channel);
        // auto p1 = send.silentSend(x, z1, prng, server_channel);

        // auto rounds = eval(p0, p1, chls[1], chls[0]);
        // if (rounds != 3)
        //   throw std::runtime_error(std::to_string(rounds) + "!=3. ");
        auto send_fn = [&send, x, &z1, &prng, channel1]() {
          send.silentSend(x, z1, prng, channel1);
        };

        auto recv_fn = [&recv, &c, &z0, &prng, channel2]() {
          recv.silentReceive(c, z0, prng, channel2);
        };

        for (u64 i = 0; i < n; ++i) {
          if (c[i].gf128Mul(x) != (z0[i] ^ z1[i])) {
            throw RTE_LOC;
          }
        }
      } else {
        // auto p0 = send.genSilentBaseOts(prng, chls[0], x);
        // auto p1 = recv.genSilentBaseOts(prng, chls[1]);

        // auto rounds = eval(p0, p1, chls[1], chls[0]);
        // if (rounds != 3)
        //   throw RTE_LOC;
        auto gen_fn1 = [&send, &prng, channel1, x]() {
          send.genSilentBaseOts(prng, channel1, x);
        };

        auto gen_fn2 = [&recv, &prng, channel2]() {
          recv.genSilentBaseOts(prng, channel2);
        };

        auto gen_fut1 = std::async(gen_fn1);
        auto gen_fut2 = std::async(gen_fn2);
        gen_fut1.get();
        gen_fut2.get();

        // p0 = send.silentSendInplace(x, n, prng, chls[0]);
        // p1 = recv.silentReceiveInplace(n, prng, chls[1]);
        // rounds = eval(p0, p1, chls[1], chls[0]);

        // for (u64 i = 0; i < n; ++i) {
        //   if (recv.mC[i].gf128Mul(x) != (send.mB[i] ^ recv.mA[i])) {
        //     throw RTE_LOC;
        //   }
        // }
        auto send_fn = [&send, x, n, &prng, channel1]() {
          send.silentSendInplace(x, n, prng, channel1);
        };

        auto recv_fn = [&recv, n, &prng, channel2]() {
          recv.silentReceiveInplace(n, prng, channel2);
        };

        auto send_fut = std::async(send_fn);
        auto recv_fut = std::async(recv_fn);
        send_fut.get();
        recv_fut.get();
      }
    }

    timer.setTimePoint("done");
  }
}

TEST(vole, silver_test) {
  using Channel = primihub::link::Channel;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "silver_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "silver_test");

  Timer timer;
  timer.setTimePoint("start");
  u64 n = 102043;
  u64 nt = std::thread::hardware_concurrency();
  block seed = block(0, 0);
  PRNG prng(seed);

  block x = prng.get();
  std::vector<block> c(n), z0(n), z1(n);

  SilentVoleReceiver recv;
  SilentVoleSender send;

  recv.mMultType = MultType::slv5;
  send.mMultType = MultType::slv5;

  recv.setTimer(timer);
  send.setTimer(timer);

  recv.mDebug = false;
  send.mDebug = false;

  // auto chls = cp::LocalAsyncSocket::makePair();

  timer.setTimePoint("ot");
  fakeBase(n, nt, prng, x, recv, send);

  // c * x = z + m

  // auto p0 = recv.silentReceive(c, z0, prng, chls[0]);
  // auto p1 = send.silentSend(x, z1, prng, chls[1]);
  // eval(p0, p1);
  auto recv_fn = [&recv, &c, &z0, &prng, channel1]() {
    recv.silentReceive(c, z0, prng, channel1);
  };

  auto send_fn = [&send, x, &z1, &prng, channel2]() {
    send.silentSend(x, z1, prng, channel2);
  };

  auto recv_fut = std::async(recv_fn);
  auto send_fut = std::async(send_fn);

  send_fut.get();
  recv_fut.get();

  timer.setTimePoint("send");
  for (u64 i = 0; i < n; ++i) {
    if (c[i].gf128Mul(x) != (z0[i] ^ z1[i])) {
      std::cout << "bad " << i << "\n  c[i] " << c[i] << " * x " << x << " = "
                << c[i].gf128Mul(x) << std::endl;
      std::cout << "  z0[i] " << z0[i] << " ^ z1 " << z1[i] << " = "
                << (z0[i] ^ z1[i]) << std::endl;
      throw RTE_LOC;
    }
  }
  timer.setTimePoint("done");
}

TEST(vole, baseot_test) {
  using Channel = primihub::link::Channel;

  Timer timer;
  timer.setTimePoint("start");
  u64 n = 123;
  block seed = block(0, 0);
  PRNG prng(seed);

  block x = prng.get();

  // auto chls = cp::LocalAsyncSocket::makePair();
  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "baseot_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "baseot_test");

  timer.setTimePoint("ot");

  // recv.mDebug = true;
  // send.mDebug = true;

  SilentVoleReceiver recv;
  SilentVoleSender send;
  // c * x = z + m

  // for (u64 n = 5000; n < 10000; ++n)
  {
    std::vector<block> c(n), z0(n), z1(n);

    recv.setTimer(timer);
    send.setTimer(timer);
    // auto p0 = recv.silentReceive(c, z0, prng, chls[0]);
    // auto p1 = send.silentSend(x, z1, prng, chls[1]);
    // eval(p0, p1);
    auto recv_fn = [&recv, &c, &z0, &prng, channel1]() {
      recv.silentReceive(c, z0, prng, channel1);
    };

    auto send_fn = [&send, x, &z1, &prng, channel2]() {
      send.silentSend(x, z1, prng, channel2);
    };

    auto send_fut = std::async(send_fn);
    auto recv_fut = std::async(recv_fn);
    send_fut.get();
    recv_fut.get();

    for (u64 i = 0; i < n; ++i) {
      if (c[i].gf128Mul(x) != (z0[i] ^ z1[i])) {
        throw RTE_LOC;
      }
    }

    timer.setTimePoint("done");
  }
}

TEST(vole, malicious_test) {
  using Channel = primihub::link::Channel;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "malicious_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "malicious_test");

  Timer timer;
  timer.setTimePoint("start");
  u64 n = 12343;
  block seed = block(0, 0);
  PRNG prng(seed);

  block x = prng.get();

  // auto chls = cp::LocalAsyncSocket::makePair();

  timer.setTimePoint("ot");

  // recv.mDebug = true;
  // send.mDebug = true;

  SilentVoleReceiver recv;
  SilentVoleSender send;

  send.mMalType = SilentSecType::Malicious;
  recv.mMalType = SilentSecType::Malicious;
  // c * x = z + m

  // for (u64 n = 5000; n < 10000; ++n)
  {
    std::vector<block> c(n), z0(n), z1(n);

    recv.setTimer(timer);
    send.setTimer(timer);
    // auto p0 = recv.silentReceive(c, z0, prng, chls[0]);
    // auto p1 = send.silentSend(x, z1, prng, chls[1]);
    // eval(p0, p1);
    auto recv_fn = [&recv, &c, &z0, &prng, channel1]() {
      recv.silentReceive(c, z0, prng, channel1);
    };

    auto send_fn = [&send, x, &z1, &prng, channel2]() {
      send.silentSend(x, z1, prng, channel2);
    };

    auto recv_fut = std::async(recv_fn);
    auto send_fut = std::async(send_fn);
    recv_fut.get();
    send_fut.get();

    for (u64 i = 0; i < n; ++i) {
      if (c[i].gf128Mul(x) != (z0[i] ^ z1[i])) {
        throw RTE_LOC;
      }
    }
    timer.setTimePoint("done");
  }
}

TEST(vole, paramsweep_test) {
  using Channel = primihub::link::Channel;

  Timer timer;
  timer.setTimePoint("start");
  block seed = block(0, 0);
  PRNG prng(seed);

  block x = prng.get();
  u64 threads = 0;

  // auto chls = cp::LocalAsyncSocket::makePair();
  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "paramsweep_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "paramsweep_test");

  timer.setTimePoint("ot");

  // recv.mDebug = true;
  // send.mDebug = true;

  SilentVoleReceiver recv;
  SilentVoleSender send;
  // c * x = z + m

  // for (u64 n = 5000; n < 10000; ++n)
  for (u64 n : {12, /* 123,465,*/ 1642, /*4356,34254,*/ 93425}) {
    std::vector<block> c(n), z0(n), z1(n);

    fakeBase(n, threads, prng, x, recv, send);

    recv.setTimer(timer);
    send.setTimer(timer);

    //  auto p0 = recv.silentReceive(c, z0, prng, chls[0]);
    //  auto p1 = send.silentSend(x, z1, prng, chls[1]);
    //  timer.setTimePoint("send");
    //  eval(p0, p1);
    auto send_fn = [&send, x, &z1, &prng, channel1]() {
      send.silentSend(x, z1, prng, channel1);
    };

    auto recv_fn = [&recv, &c, &z0, &prng, channel2]() {
      recv.silentReceive(c, z0, prng, channel2);
    };

    auto recv_fut = std::async(recv_fn);
    auto send_fut = std::async(send_fn);
    recv_fut.get();
    send_fut.get();

    for (u64 i = 0; i < n; ++i) {
      if (c[i].gf128Mul(x) != (z0[i] ^ z1[i])) {
        throw RTE_LOC;
      }
    }
    timer.setTimePoint("done");
  }
}
