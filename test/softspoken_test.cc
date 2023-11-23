#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Matrix.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include <random>
#include <thread>
#include <vector>

#include "network/mem_channel.h"
#include "psi/ot/base/otextinterface.h"
#include "psi/ot/twochooseone/softspokenot/softspokenmalotext.h"
#include "psi/ot/twochooseone/softspokenot/softspokenshotext.h"
#include "psi/ot/vole/softspokenot/smallfieldvole.h"
#include "test/ot_tests.h"

using osuCrypto::BitVector;
using osuCrypto::block;
using osuCrypto::PRNG;
using primihub::crypto::OT_100Receive_Test;
using primihub::crypto::SmallFieldVoleBase;
using primihub::crypto::SmallFieldVoleReceiver;
using primihub::crypto::SmallFieldVoleSender;
using primihub::crypto::SoftSpokenMalOtReceiver;
using primihub::crypto::SoftSpokenMalOtSender;
using primihub::crypto::SoftSpokenShOtReceiver;
using primihub::crypto::SoftSpokenShOtSender;
using primihub::crypto::tests::xorReduction;
using primihub::link::MemoryChannel;

TEST(softspokenot, smallfieldvole) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  xorReduction();

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "smallfield_vole");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "smallfield_vole");

  const bool print = false;

  PRNG prng0(block(4234385, 3445235));
  PRNG prng1(block(42348395, 989835));

  u64 numVoles = 128;

  for (size_t fieldBits = 1; fieldBits <= 10; fieldBits += 3) {
    for (int malicious = 0; malicious < 2; ++malicious) {
      const size_t nBaseOTs =
          SmallFieldVoleBase::baseOtCount(fieldBits, numVoles);

      std::vector<std::array<block, 2>> baseSend(nBaseOTs);
      std::vector<block> baseRecv(nBaseOTs);
      BitVector baseChoice(nBaseOTs);
      baseChoice.randomize(prng0);

      prng0.get(baseSend.data(), baseSend.size());
      for (u64 i = 0; i < nBaseOTs; ++i)
        baseRecv[i] = baseSend[i][baseChoice[i]];

      SmallFieldVoleSender sender;
      SmallFieldVoleReceiver recver;

      recver.init(fieldBits, numVoles, malicious);
      sender.init(fieldBits, numVoles, malicious);

      std::vector<block> u(sender.uPadded()), v(sender.vPadded()),
          w(recver.wPadded());

      sender.setBaseOts(baseSend);
      recver.setBaseOts(baseRecv, baseChoice);

      auto sender_fn = [channel1, &sender, &prng1]() {
        sender.expand(channel1, prng1, 1);
      };

      auto recver_fn = [channel2, &recver, &prng0]() {
        recver.expand(channel2, prng0, 1);
      };

      auto sender_fut = std::async(sender_fn);
      auto recver_fut = std::async(recver_fn);

      sender_fut.get();
      recver_fut.get();

      sender.generate(0, mAesFixedKey, u, v);
      recver.generate(0, mAesFixedKey, w);

      if (sender.vSize() != recver.wSize())
        throw std::runtime_error(
            "Mismatch of sender.vSize() and recver.wSize().");
      if (sender.uSize() > u.size())
        throw std::runtime_error(
            "Mismatch of sender.uSize() and recver.uSize().");
      if (sender.vSize() > v.size() || recver.wSize() > w.size())
        throw std::runtime_error("vSize or wSize mismatch.");

      u.resize(numVoles);

      BitVector delta = recver.mDelta;
      if (print) {
        std::cout << "Delta:\n";
        for (size_t i = 0; i < delta.sizeBlocks(); ++i)
          std::cout << delta.blocks()[i] << ", ";

        std::cout << "\nSeeds:\n";
      }

      size_t fieldSize = recver.fieldSize();
      for (size_t i = 0; i < numVoles; ++i) {
        size_t deltaI = 0;
        for (size_t j = 0; j < fieldBits; ++j)
          deltaI += (size_t)delta[i * fieldBits + j] << j;

        if (print) {
          for (size_t j = 0; j < fieldSize; ++j)
            std::cout << j << ": " << sender.mSeeds[i * fieldSize + j] << '\n';
          for (size_t j = 1; j < fieldSize; ++j)
            std::cout << j << ": " << recver.mSeeds[i * (fieldSize - 1) + j - 1]
                      << '\n';
        }

        for (size_t j = 0; j < fieldSize; ++j) {
          if (j == deltaI)
            // Punctured point.
            continue;

          block senderSeed = sender.mSeeds[i * fieldSize + j];
          block recvSeed =
              recver.mSeeds[i * (fieldSize - 1) + (j ^ deltaI) - 1];
          if (senderSeed != recvSeed)
            throw std::runtime_error("seed mismatch error.");
        }
      }

      if (print) std::cout << "\nOutputs:\n";

      std::vector<block> shouldEqualV = w;
      recver.sharedFunctionXor(span<const block>(u), span<block>(shouldEqualV));
      for (size_t i = 0; i < recver.wSize(); ++i) {
        if (print) {
          std::cout << u[i] << '\n';
          std::cout << v[i] << '\n';
          std::cout << shouldEqualV[i] << '\n';
          std::cout << w[i] << '\n';
        }
        if (v[i] != shouldEqualV[i])
          throw std::runtime_error(
              "Value mismatch found when compare to shouldEqualV.");

        if (v[i] !=
            (w[i] ^ (block::allSame((bool)delta[i]) & u[i / fieldBits])))
          throw std::runtime_error("Value mismatch found when compare to w.");
      }
    }
  }
}

TEST(softspokenot, semihost) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "semihost");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "semihost");

  PRNG prng0(block(4234335, 3445235));
  PRNG prng1(block(42348345, 989835));

  uint64_t nnumOTs[3] = {10, 100, 9733};

  for (auto random : {false, true}) {
    for (auto numOTs : nnumOTs) {
      for (size_t fieldBits = 1; fieldBits <= 11; fieldBits += 3) {
        SoftSpokenShOtSender<> sender;
        SoftSpokenShOtReceiver<> recver;

        sender.init(fieldBits, random);
        recver.init(fieldBits, random);

        const size_t nBaseOTs = sender.baseOtCount();
        if (nBaseOTs != recver.baseOtCount())
          throw std::runtime_error("Ot count mismatch error.");

        AlignedVector<block> recvMsg(numOTs), baseRecv(nBaseOTs);
        AlignedVector<std::array<block, 2>> sendMsg(numOTs), baseSend(nBaseOTs);
        BitVector choices(numOTs), baseChoice(nBaseOTs);

        choices.randomize(prng0);
        baseChoice.randomize(prng0);

        prng0.get(baseSend.data(), baseSend.size());
        for (u64 i = 0; i < nBaseOTs; ++i)
          baseRecv[i] = baseSend[i][baseChoice[i]];

        recver.setBaseOts(baseSend);
        sender.setBaseOts(baseRecv, baseChoice);

        auto sender_fn = [&sender, &sendMsg, &prng1, channel1]() {
          sender.send(sendMsg, prng1, channel1);
        };

        auto recver_fn = [&recver, &choices, &recvMsg, &prng0, channel2]() {
          recver.receive(choices, recvMsg, prng0, channel2);
        };

        auto sender_fut = std::async(sender_fn);
        auto recver_fut = std::async(recver_fn);
        sender_fut.get();
        recver_fut.get();

        // for (u64 i = 0; i < numOTs; ++i)
        //{
        //    std::cout << sendMsg[i][0] << ", " << sendMsg[i][1] << ", " <<
        //    recvMsg[i] << "," << std::endl;
        //}
        // std::cout << std::endl;

        OT_100Receive_Test(choices, recvMsg, sendMsg);

        if (random == false) {
          const block delta = sender.delta();
          for (auto &s : sendMsg)
            if (neq(s[0] ^ delta, s[1]))
              throw std::runtime_error("Value mismatch error.");
        }
      }
    }
  }
}

TEST(softspokenot, semihost_split) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "semihost_split");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "semihost_split");

  PRNG prng0(block(4234335, 3445235));
  PRNG prng1(block(42348345, 989835));

  auto numOTs = 1231;

  SoftSpokenShOtSender<> sender;
  SoftSpokenShOtReceiver<> recver;

  const size_t nBaseOTs = sender.baseOtCount();
  if (nBaseOTs != recver.baseOtCount())
    throw std::runtime_error("Ot count mismatch error.");

  AlignedVector<block> recvMsg(numOTs), baseRecv(nBaseOTs);
  AlignedVector<std::array<block, 2>> sendMsg(numOTs), baseSend(nBaseOTs);
  BitVector choices(numOTs), baseChoice(nBaseOTs);

  choices.randomize(prng0);
  baseChoice.randomize(prng0);

  prng0.get(baseSend.data(), baseSend.size());
  for (u64 i = 0; i < nBaseOTs; ++i) baseRecv[i] = baseSend[i][baseChoice[i]];

  recver.setBaseOts(baseSend);
  sender.setBaseOts(baseRecv, baseChoice);

  auto recver_fn = [&recver, &choices, &recvMsg, &prng0, channel1]() {
    recver.receive(choices, recvMsg, prng0, channel1);
  };

  auto sender_fn = [&sender, &sendMsg, &prng1, channel2]() {
    sender.send(sendMsg, prng1, channel2);
  };

  auto sender_fut = std::async(sender_fn);
  auto recver_fut = std::async(recver_fn);

  sender_fut.get();
  recver_fut.get();

  OT_100Receive_Test(choices, recvMsg, sendMsg);

  auto recver2 = recver.splitBase();
  auto sender2 = sender.splitBase();

  auto recver_fn2 = [&recver2, &choices, &recvMsg, &prng0, channel1]() {
    recver2.receive(choices, recvMsg, prng0, channel1);
  };

  auto sender_fn2 = [&sender2, &sendMsg, &prng1, channel2]() {
    sender2.send(sendMsg, prng1, channel2);
  };

  auto sender_fut2 = std::async(sender_fn2);
  auto recver_fut2 = std::async(recver_fn2);

  sender_fut2.get();
  recver_fut2.get();

  OT_100Receive_Test(choices, recvMsg, sendMsg);
}

TEST(softspokenot, maliciousleaky) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "maliciousleaky");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "maliciousleaky");

  PRNG prng0(block(4234335, 3445235));
  PRNG prng1(block(42348345, 989835));

  uint64_t nnumOTs[1] = {9733};

  for (auto numOTs : nnumOTs) {
    for (size_t fieldBits = 1; fieldBits <= 11; fieldBits += 3) {
      SoftSpokenMalOtSender sender;
      SoftSpokenMalOtReceiver recver;

      sender.init(fieldBits, false);
      recver.init(fieldBits, false);

      const size_t nBaseOTs = sender.baseOtCount();
      if (nBaseOTs != recver.baseOtCount())
        throw std::runtime_error("Ot count mismatch.");

      std::vector<block> baseRecv(nBaseOTs);
      std::vector<std::array<block, 2>> baseSend(nBaseOTs);
      BitVector choices(numOTs), baseChoice(nBaseOTs);
      choices.randomize(prng0);
      baseChoice.randomize(prng0);

      prng0.get((u8 *)baseSend.data()->data(),
                sizeof(block) * 2 * baseSend.size());
      for (u64 i = 0; i < nBaseOTs; ++i) {
        baseRecv[i] = baseSend[i][baseChoice[i]];
      }

      AlignedVector<block> recvMsg(numOTs);
      AlignedVector<std::array<block, 2>> sendMsg(numOTs);

      memset(recvMsg.data(), 0xcc, numOTs * sizeof(block));
      block bb0, bb1;
      memset(bb0.data(), 0xc1, sizeof(block));
      memset(bb1.data(), 0xc2, sizeof(block));
      for (u64 i = 0; i < numOTs; ++i) {
        sendMsg[i][0] = bb0;
        sendMsg[i][1] = bb1;
      }

      recver.setBaseOts(baseSend);
      sender.setBaseOts(baseRecv, baseChoice);

      auto sender_fn = [&sender, &sendMsg, &prng1, channel1]() {
        sender.send(sendMsg, prng1, channel1);
      };

      auto recver_fn = [&recver, &choices, &recvMsg, &prng0, channel2]() {
        recver.receive(choices, recvMsg, prng0, channel2);
      };

      auto sender_fut = std::async(sender_fn);
      auto recver_fut = std::async(recver_fn);

      sender_fut.get();
      recver_fut.get();

      OT_100Receive_Test(choices, recvMsg, sendMsg);

      const block delta = sender.delta();
      for (auto &s : sendMsg) {
        if (s[0] == bb0 || s[1] == bb1)
          throw std::runtime_error("Value mismatch error.");

        if (neq(s[0] ^ delta, s[1]))
          throw std::runtime_error("Value equal error.");
      }
    }
  }
}

TEST(softspokenot, malicious21) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "malicious21");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "malicious21");

  PRNG prng0(block(4234335, 3445235));
  PRNG prng1(block(42348345, 989835));

  uint64_t nnumOTs[1] = {9733};

  for (auto numOTs : nnumOTs) {
    for (size_t fieldBits = 1; fieldBits <= 11; fieldBits += 3) {
      // SoftSpokenMalOtSender sender;
      // SoftSpokenMalOtReceiver recver;
      // sender.init(fieldBits);
      // recver.init(fieldBits);

      SoftSpokenMalOtSender sender;
      SoftSpokenMalOtReceiver recver;
      sender.init(fieldBits, true);
      recver.init(fieldBits, true);

      size_t nBaseOTs = sender.baseOtCount();
      if (nBaseOTs != recver.baseOtCount())
        throw std::runtime_error("Ot count mismatch error.");

      std::vector<block> baseRecv(nBaseOTs);
      std::vector<std::array<block, 2>> baseSend(nBaseOTs);
      BitVector choices(numOTs), baseChoice(nBaseOTs);
      choices.randomize(prng0);
      baseChoice.randomize(prng0);

      prng0.get((u8 *)baseSend.data()->data(),
                sizeof(block) * 2 * baseSend.size());
      for (u64 i = 0; i < nBaseOTs; ++i) {
        baseRecv[i] = baseSend[i][baseChoice[i]];
      }

      AlignedVector<block> recvMsg(numOTs);
      AlignedVector<std::array<block, 2>> sendMsg(numOTs);

      recver.setBaseOts(baseSend);
      sender.setBaseOts(baseRecv, baseChoice);

      auto sender_fn = [&sender, &sendMsg, &prng1, channel1]() {
        sender.send(sendMsg, prng1, channel1);
      };

      auto recver_fn = [&recver, &choices, &recvMsg, &prng0, channel2]() {
        recver.receive(choices, recvMsg, prng0, channel2);
      };

      auto sender_fut = std::async(sender_fn);
      auto recver_fut = std::async(recver_fn);

      sender_fut.get();
      recver_fut.get();

      OT_100Receive_Test(choices, recvMsg, sendMsg);
    }
  }
}

TEST(softspokenot, malicious21_split) {
  using Channel = primihub::link::Channel;
  using ChannelRole = MemoryChannel::ChannelRole;

  auto channel_impl1 = std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  auto channel1 = std::make_shared<Channel>(channel_impl1, "malicious21_split");

  auto channel_impl2 = std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  auto channel2 = std::make_shared<Channel>(channel_impl2, "malicious21_split");

  PRNG prng0(block(4234335, 3445235));
  PRNG prng1(block(42348345, 989835));

  auto numOTs = 9733;

  SoftSpokenMalOtSender sender;
  SoftSpokenMalOtReceiver recver;

  size_t nBaseOTs = sender.baseOtCount();
  if (nBaseOTs != recver.baseOtCount())
    throw std::runtime_error("Ot count mismatch error.");

  std::vector<block> baseRecv(nBaseOTs);
  std::vector<std::array<block, 2>> baseSend(nBaseOTs);
  BitVector choices(numOTs), baseChoice(nBaseOTs);
  choices.randomize(prng0);
  baseChoice.randomize(prng0);

  prng0.get((u8 *)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
  for (u64 i = 0; i < nBaseOTs; ++i) {
    baseRecv[i] = baseSend[i][baseChoice[i]];
  }

  AlignedVector<block> recvMsg(numOTs);
  AlignedVector<std::array<block, 2>> sendMsg(numOTs);

  recver.setBaseOts(baseSend);
  sender.setBaseOts(baseRecv, baseChoice);

  auto sender1_fn = [&sender, &sendMsg, &prng1, channel1]() {
    sender.send(sendMsg, prng1, channel1);
  };

  auto recver1_fn = [&recver, &choices, &recvMsg, &prng0, channel2]() {
    recver.receive(choices, recvMsg, prng0, channel2);
  };

  auto sender_fut1 = std::async(sender1_fn);
  auto recver_fut1 = std::async(recver1_fn);

  sender_fut1.get();
  recver_fut1.get();

  OT_100Receive_Test(choices, recvMsg, sendMsg);

  auto recver2 = recver.splitBase();
  auto sender2 = sender.splitBase();

  auto sender2_fn = [&sender2, &sendMsg, &prng1, channel1]() {
    sender2.send(sendMsg, prng1, channel1);
  };

  auto recver2_fn = [&recver2, &choices, &recvMsg, &prng0, channel2]() {
    recver2.receive(choices, recvMsg, prng0, channel2);
  };

  auto sender_fut2 = std::async(sender2_fn);
  auto recver_fut2 = std::async(recver2_fn);

  sender_fut2.get();
  recver_fut2.get();

  OT_100Receive_Test(choices, recvMsg, sendMsg);
}
