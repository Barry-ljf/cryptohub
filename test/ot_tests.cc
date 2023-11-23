#include "test/ot_tests.h"

using namespace osuCrypto;

namespace primihub::crypto {
void OT_100Receive_Test(BitVector &choiceBits, span<block> recv,
                        span<std::array<block, 2>> sender) {
  for (u64 i = 0; i < choiceBits.size(); ++i) {
    u8 choice = choiceBits[i];
    const block &revcBlock = recv[i];
    const block &senderBlock = sender[i][choice];

    if (revcBlock == ZeroBlock)
      throw std::runtime_error("Runtime logic error.");

    if (neq(revcBlock, senderBlock))
      throw std::runtime_error("Mismatch between recv block and sender block.");

    if (eq(revcBlock, sender[i][1 ^ choice]))
      throw std::runtime_error(
          "Mismatch between recv block and sender block with choice.");
  }
}
}  // namespace primihub::crypto
