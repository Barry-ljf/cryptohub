#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>

#include "psi/ot/vole/noisy/noisyvolesender.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;

void NoisyVoleSender::send(block x, span<block> z, PRNG &prng, OtReceiver &ot,
                           std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, x, z, &prng, &ot, &chl, bv = BitVector((u8 *)&x,
  // 128),
  //          otMsg = AlignedUnVector<block>{128});
  BitVector bv((u8 *)&x, 128);
  AlignedUnVector<block> otMsg{128};

  setTimePoint("NoisyVoleSender.ot.begin");

  // BitVector bv((u8*)&x, 128);
  // std::array<block, 128> otMsg;
  // MC_AWAIT(ot.receive(bv, otMsg, prng, chl));
  ot.receive(bv, otMsg, prng, chl);
  setTimePoint("NoisyVoleSender.ot.end");

  // MC_AWAIT(send(x, z, prng, otMsg, chl));
  send(x, z, prng, otMsg, chl);
}

void NoisyVoleSender::send(block x, span<block> z, PRNG &prng,
                           span<block> otMsg,
                           std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, x, z, &prng, otMsg, &chl, msg = Matrix<block>{},
  //          buffer = std::vector<block>{}, xIter = BitIterator{});
  Matrix<block> msg{};
  std::vector<block> buffer{};
  BitIterator xIter{};

  if (otMsg.size() != 128)
    throw RTE_LOC;
  setTimePoint("NoisyVoleSender.main");

  msg.resize(otMsg.size(), z.size());
  memset(z.data(), 0, sizeof(block) * z.size());

  // MC_AWAIT(chl.recv(msg));
  // chl.recv(msg);
  auto fut = chl->asyncRecv(msg);
  auto status = fut.get();
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv error.";
    throw std::runtime_error("Recv failed.");
  }

  setTimePoint("NoisyVoleSender.recvMsg");
  buffer.resize(z.size());

  xIter = BitIterator((u8 *)&x);

  for (u64 i = 0; i < otMsg.size(); ++i, ++xIter) {
    PRNG pi(otMsg[i]);
    pi.get<block>(buffer);

    if (*xIter) {
      for (u64 j = 0; j < z.size(); ++j) {
        buffer[j] = msg(i, j) ^ buffer[j];
      }
    }

    for (u64 j = 0; j < (u64)z.size(); ++j) {
      z[j] = z[j] ^ buffer[j];
    }
  }
  setTimePoint("NoisyVoleSender.done");
}
} // namespace primihub::crypto
