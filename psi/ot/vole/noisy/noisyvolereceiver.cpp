#include <cryptoTools/Common/BitIterator.h>
#include <cryptoTools/Common/Matrix.h>

#include "psi/ot/vole/noisy/noisyvolereceiver.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;

void NoisyVoleReceiver::receive(span<block> y, span<block> z, PRNG &prng,
                                OtSender &ot,
                                std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, y, z, &prng, &ot, &chl,
  //          otMsg = AlignedUnVector<std::array<block, 2>>{128});
  AlignedUnVector<std::array<block, 2>> otMsg{128};

  setTimePoint("NoisyVoleReceiver.ot.begin");

  // MC_AWAIT(ot.send(otMsg, prng, chl));
  ot.send(otMsg, prng, chl);

  setTimePoint("NoisyVoleReceiver.ot.end");

  // MC_AWAIT(receive(y, z, prng, otMsg, chl));
  receive(y, z, prng, otMsg, chl);
}

void NoisyVoleReceiver::receive(span<block> y, span<block> z, PRNG &_,
                                span<std::array<block, 2>> otMsg,
                                std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, y, z, otMsg, &chl, msg = Matrix<block>{},
  //          prng = std::move(PRNG{})
  //          // buffer = std::vector<block>{}
  // );
  PRNG prng = std::move(PRNG{});
  Matrix<block> msg{};

  setTimePoint("NoisyVoleReceiver.begin");
  if (otMsg.size() != 128)
    throw RTE_LOC;
  if (y.size() != z.size())
    throw RTE_LOC;
  if (z.size() == 0)
    throw RTE_LOC;

  memset(z.data(), 0, sizeof(block) * z.size());
  msg.resize(otMsg.size(), y.size());

  // buffer.resize(z.size());

  for (u64 ii = 0; ii < (u64)otMsg.size(); ++ii) {
    // PRNG p0(otMsg[ii][0]);
    // PRNG p1(otMsg[ii][1]);
    prng.SetSeed(otMsg[ii][0], z.size());
    auto &buffer = prng.mBuffer;

    for (u64 j = 0; j < (u64)y.size(); ++j) {
      z[j] = z[j] ^ buffer[j];

      block twoPowI = ZeroBlock;
      *BitIterator((u8 *)&twoPowI, ii) = 1;

      auto yy = y[j].gf128Mul(twoPowI);

      msg(ii, j) = yy ^ buffer[j];
    }

    prng.SetSeed(otMsg[ii][1], z.size());

    for (u64 j = 0; j < (u64)y.size(); ++j) {
      // enc one message under the OT msg.
      msg(ii, j) = msg(ii, j) ^ buffer[j];
    }
  }

  // MC_AWAIT(chl.send(std::move(msg)));
  // chl.send(std::move(msg));
  auto status = chl->asyncSend(std::move(msg));
  if (!status.IsOK()) {
    LOG(ERROR) << "Send content in msg failed.";
    throw std::runtime_error("Send content in msg failed.");
  }

  // chl.asyncSend(std::move(msg));
  setTimePoint("NoisyVoleReceiver.done");
}
} // namespace primihub::crypto
