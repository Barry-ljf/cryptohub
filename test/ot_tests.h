#ifndef OT_TEST_H_
#define OT_TEST_H_

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>

namespace primihub::crypto {
void OT_100Receive_Test(
    osuCrypto::BitVector &choiceBits, osuCrypto::span<osuCrypto::block> recv,
    osuCrypto::span<std::array<osuCrypto::block, 2>> sender);
}

#endif
