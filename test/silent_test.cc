#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Network/IOService.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include "network/mem_channel.h"
#include "psi/ot/tools/silentpprf.h"
#include "psi/ot/twochooseone/silent/silentotextreceiver.h"
#include "psi/ot/twochooseone/silent/silentotextsender.h"

extern bool primihub::crypto::gSilverWarning;

using osuCrypto::BitVector;
using osuCrypto::block;
using osuCrypto::PRNG;
using primihub::crypto::ChoiceBitPacking;
using primihub::crypto::MultType;
using primihub::crypto::OTType;
using primihub::crypto::SilentOtExtReceiver;
using primihub::crypto::SilentOtExtSender;
using primihub::link::Channel;
using primihub::link::MemoryChannel;
using ChannelRole = MemoryChannel::ChannelRole;

namespace {
void fakeBase(u64 n, u64 s, u64 threads, PRNG &prng,
              SilentOtExtReceiver &recver, SilentOtExtSender &sender) {
  sender.configure(n, s, threads);
  auto count = sender.silentBaseOtCount();
  std::vector<std::array<block, 2>> msg2(count);
  for (u64 i = 0; i < msg2.size(); ++i) {
    msg2[i][0] = prng.get();
    msg2[i][1] = prng.get();
  }
  sender.setSilentBaseOts(msg2);

  // fake base OTs.
  {
    recver.configure(n, s, threads);
    BitVector choices = recver.sampleBaseChoiceBits(prng);
    std::vector<block> msg(choices.size());
    for (u64 i = 0; i < msg.size(); ++i) msg[i] = msg2[i][choices[i]];
    recver.setSilentBaseOts(msg);
  }
}

void checkRandom(span<block> messages, span<std::array<block, 2>> messages2,
                 BitVector &choice, u64 n, bool verbose) {
  if (messages.size() != n) throw RTE_LOC;
  if (messages2.size() != n) throw RTE_LOC;
  if (choice.size() != n) throw RTE_LOC;
  bool passed = true;

  for (u64 i = 0; i < n; ++i) {
    block m1 = messages[i];
    block m2a = messages2[i][0];
    block m2b = (messages2[i][1]);
    u8 c = choice[i];

    std::array<bool, 2> eqq{eq(m1, m2a), eq(m1, m2b)};
    if (eqq[c ^ 1] == true) {
      passed = false;
      if (verbose) std::cout << Color::Pink;
    }
    if (eqq[0] == false && eqq[1] == false) {
      passed = false;
      if (verbose) std::cout << Color::Red;
    }

    if (eqq[c] == false && verbose)
      std::cout << "m" << i << " " << m1 << " != (" << m2a << " " << m2b << ")_"
                << (int)c << "\n";
  }

  if (passed == false) throw RTE_LOC;
}

template <typename Choice>
void checkCorrelated(span<block> Ar, span<block> Bs, Choice &choice,
                     block delta, u64 n, bool verbose,
                     ChoiceBitPacking packing) {
  if (Ar.size() != n) throw RTE_LOC;
  if (Bs.size() != n) throw RTE_LOC;
  if (packing == ChoiceBitPacking::False && (u64)choice.size() != n)
    throw RTE_LOC;
  bool passed = true;
  // bool first = true;
  block mask = AllOneBlock ^ OneBlock;

  for (u64 i = 0; i < n; ++i) {
    block m1 = Ar[i];
    block m2a = Bs[i];
    block m2b = (Bs[i] ^ delta);
    u8 c, c2;

    if (packing == ChoiceBitPacking::True) {
      c = u8((m1 & OneBlock) == OneBlock) & 1;
      m1 = m1 & mask;
      m2a = m2a & mask;
      m2b = m2b & mask;

      if (choice.size()) {
        c2 = choice[i];

        if (c2 != c) throw RTE_LOC;
      }
    } else {
      c = choice[i];
    }

    std::array<bool, 2> eqq{eq(m1, m2a), eq(m1, m2b)};

    bool good = true;
    if (eqq[c] == false || eqq[c ^ 1] == true) {
      good = passed = false;
      // if (verbose)
      std::cout << Color::Pink;
    }
    if (eqq[0] == false && eqq[1] == false) {
      good = passed = false;
      // if (verbose)
      std::cout << Color::Red;
    }

    if (!good /*&& first*/) {
      // first = false;
      std::cout << i << " m " << mask << std::endl;
      std::cout << "r " << m1 << " " << int(c) << std::endl;
      std::cout << "s " << m2a << " " << m2b << std::endl;
      std::cout << "d " << (m1 ^ m2a) << " " << (m1 ^ m2b) << std::endl;
    }

    std::cout << Color::Default;
  }

  if (passed == false) throw RTE_LOC;
}

};  // namespace

TEST(silentot, silver_test) {
  using Channel = primihub::link::Channel;
  primihub::crypto::gSilverWarning = false;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "silver_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "silver_test");

  std::vector<u64> nn = {/*12, 134, 600,*/ 1234 /*, 14366 */};

  bool verbose = false;
  u64 threads = 4;
  u64 s = 2;

  PRNG prng(toBlock(static_cast<uint64_t>(0)));
  PRNG prng1(toBlock(static_cast<uint64_t>(1)));

  SilentOtExtSender sender;
  SilentOtExtReceiver recver;

  sender.mMultType = MultType::slv5;
  recver.mMultType = MultType::slv5;

  // sender.mDebug = true;
  // recver.mDebug = true;

  block delta = prng.get();
  // auto type = OTType::Correlated;

  for (auto n : nn) {
    // block delta
    std::vector<std::array<block, 2>> msg2(n);
    std::vector<block> msg1(n);
    BitVector choice(n);

    fakeBase(n, s, threads, prng, recver, sender);
    // auto p0 = sender.silentSend(msg2, prng, sockets[0]);
    // auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);
    auto send_fn = [&sender, &msg2, &prng, channel1]() {
      sender.silentSend(msg2, prng, channel1);
    };

    auto recv_fn = [&recver, &choice, &msg1, &prng, channel2]() {
      recver.silentReceive(choice, msg1, prng, channel2);
    };

    auto send_fut = std::async(send_fn);
    auto recv_fut = std::async(recv_fn);

    send_fut.get();
    recv_fut.get();

    checkRandom(msg1, msg2, choice, n, verbose);

    auto type = ChoiceBitPacking::False;
    fakeBase(n, s, threads, prng, recver, sender);
    // p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
    // p1 = recver.silentReceiveInplace(n, prng, sockets[1], type);
    auto send_fn2 = [&sender, &delta, n, &prng, channel1]() {
      sender.silentSendInplace(delta, n, prng, channel1);
    };

    auto recv_fn2 = [&recver, n, &prng, channel2, type]() {
      recver.silentReceiveInplace(n, prng, channel2, type);
    };

    auto send_fut2 = std::async(send_fn2);
    auto recv_fut2 = std::async(recv_fn2);
    send_fut2.get();
    recv_fut2.get();

    // eval(p0, p1);

    checkCorrelated(recver.mA, sender.mB, recver.mC, delta, n, verbose, type);
  }
}

TEST(silentot, baseot_test) {
  using Channel = primihub::link::Channel;
  primihub::crypto::gSilverWarning = false;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "baseot_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "baseot_test");

  u64 n = 123;
  bool verbose = false;

  PRNG prng(toBlock(static_cast<uint64_t>(0)));
  PRNG prng1(toBlock(static_cast<uint64_t>(1)));

  SilentOtExtSender sender;
  SilentOtExtReceiver recver;

  // block delta = prng.get();
  // auto type = OTType::Correlated;

  std::vector<std::array<block, 2>> msg2(n);
  std::vector<block> msg1(n);
  BitVector choice(n);

  // auto p0 = sender.silentSend(msg2, prng, sockets[0]);
  // auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);
  auto send_fn = [&sender, &msg2, &prng, channel1]() {
    sender.silentSend(msg2, prng, channel1);
  };

  auto recv_fn = [&recver, &choice, &msg1, &prng, channel2]() {
    recver.silentReceive(choice, msg1, prng, channel2);
  };

  auto recv_fut = std::async(recv_fn);
  auto send_fut = std::async(send_fn);

  send_fut.get();
  recv_fut.get();

  // eval(p0, p1);

  checkRandom(msg1, msg2, choice, n, verbose);
}

TEST(silentot, correlated_test) {
  primihub::crypto::gSilverWarning = false;
  using Channel = primihub::link::Channel;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "correlated_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "correlated_test");

  u64 n = 10;
  bool verbose = false;
  u64 threads = 4;
  u64 s = 2;

  PRNG prng(toBlock(static_cast<uint64_t>(0)));
  PRNG prng1(toBlock(static_cast<uint64_t>(1)));

  SilentOtExtSender sender;
  SilentOtExtReceiver recver;
  fakeBase(n, s, threads, prng, recver, sender);

  block delta = prng.get();

  std::vector<block> messages2(n);
  BitVector choice(n);
  std::vector<block> messages(n);
  auto type = OTType::Correlated;

  // auto p0 = sender.silentSend(delta, messages, prng, sockets[0]);
  // auto p1 = recver.silentReceive(choice, messages2, prng, sockets[1], type);
  auto send_fn = [&sender, &delta, &messages, &prng, channel1]() {
    sender.silentSend(delta, messages, prng, channel1);
  };

  auto recv_fn = [&recver, &choice, &messages2, &prng, channel2, type]() {
    recver.silentReceive(choice, messages2, prng, channel2, type);
  };

  auto send_fut = std::async(send_fn);
  auto recv_fut = std::async(recv_fn);

  send_fut.get();
  recv_fut.get();

  // eval(p0, p1);

  checkCorrelated(messages, messages2, choice, delta, n, verbose,
                  ChoiceBitPacking::False);
}

TEST(silentot, inplace_test) {
  primihub::crypto::gSilverWarning = false;
  using Channel = primihub::link::Channel;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "inplace_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "inplace_test");
  // auto sockets = cp::LocalAsyncSocket::makePair();

  u64 n = 10000;
  bool verbose = false;
  u64 threads = 4;
  u64 s = 2;

  PRNG prng(toBlock(static_cast<uint64_t>(0)));
  PRNG prng1(toBlock(static_cast<uint64_t>(1)));

  SilentOtExtSender sender;
  SilentOtExtReceiver recver;

  block delta = prng.get();

  // auto type = OTType::Correlated;

  {
    fakeBase(n, s, threads, prng, recver, sender);
    // auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
    // auto p1 = recver.silentReceiveInplace(n, prng, sockets[1]);
    // eval(p0, p1);
    auto send_fn = [&sender, delta, n, channel1]() {
      PRNG prng(toBlock(static_cast<uint64_t>(0)));
      sender.silentSendInplace(delta, n, prng, channel1);
    };

    auto recv_fn = [&recver, n, channel2]() {
      PRNG prng(toBlock(static_cast<uint64_t>(0)));
      recver.silentReceiveInplace(n, prng, channel2);
    };

    auto send_fut = std::async(send_fn);
    auto recv_fut = std::async(recv_fn);
    send_fut.get();
    recv_fut.get();

    auto &messages = recver.mA;
    auto &messages2 = sender.mB;
    auto &choice = recver.mC;
    checkCorrelated(messages, messages2, choice, delta, n, verbose,
                    ChoiceBitPacking::False);
  }

  {
    fakeBase(n, s, threads, prng, recver, sender);
    // auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
    // auto p1 = recver.silentReceiveInplace(n, prng, sockets[1],
    //                                       ChoiceBitPacking::True);
    // eval(p0, p1);
    auto send_fn = [&sender, delta, n, channel1]() {
      PRNG prng(toBlock(static_cast<uint64_t>(0)));
      sender.silentSendInplace(delta, n, prng, channel1);
    };

    auto recv_fn = [&recver, n, channel2]() {
      PRNG prng(toBlock(static_cast<uint64_t>(0)));
      recver.silentReceiveInplace(n, prng, channel2, ChoiceBitPacking::True);
    };

    auto send_fut = std::async(send_fn);
    auto recv_fut = std::async(recv_fn);
    send_fut.get();
    recv_fut.get();

    auto &messages = recver.mA;
    auto &messages2 = sender.mB;
    auto &choice = recver.mC;
    checkCorrelated(messages, messages2, choice, delta, n, verbose,
                    ChoiceBitPacking::True);
  }
}

TEST(silentot, paramsweep_test) {
  primihub::crypto::gSilverWarning = false;
  using Channel = primihub::link::Channel;

  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "paramsweep_test");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "paramsweep_test");
  // auto sockets = cp::LocalAsyncSocket::makePair();

  std::vector<u64> nn = {12, /*134,*/ 433, /*4234,*/ 5466};

  bool verbose = false;
  u64 threads = 4;
  u64 s = 2;

  PRNG prng(toBlock(static_cast<uint64_t>(0)));
  PRNG prng1(toBlock(static_cast<uint64_t>(1)));

  SilentOtExtSender sender;
  SilentOtExtReceiver recver;

  block delta = prng.get();
  // auto type = OTType::Correlated;

  for (auto n : nn) {
    fakeBase(n, s, threads, prng, recver, sender);

    // auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
    // auto p1 = recver.silentReceiveInplace(n, prng, sockets[1]);
    // eval(p0, p1);
    auto send_fn = [&sender, delta, n, &prng, channel1]() {
      sender.silentSendInplace(delta, n, prng, channel1);
    };

    auto recv_fn = [&recver, n, &prng, channel2]() {
      recver.silentReceiveInplace(n, prng, channel2);
    };

    auto send_fut = std::async(send_fn);
    auto recv_fut = std::async(recv_fn);
    send_fut.get();
    recv_fut.get();

    checkCorrelated(sender.mB, recver.mA, recver.mC, delta, n, verbose,
                    ChoiceBitPacking::False);
  }
}
