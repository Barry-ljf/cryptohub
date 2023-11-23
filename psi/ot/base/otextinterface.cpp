#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Network/Channel.h>
#include <vector>

#include "psi/ot/base/baseot.h"
#include "psi/ot/base/otextinterface.h"

// void OtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
//{
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
// void OtExtReceiver::genBaseOts(OtSender& base, PRNG& prng, Channel& chl)
//{
//
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(base, prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
// void OtExtSender::genBaseOts(PRNG & prng, Channel & chl)
//{
//
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
// void OtExtSender::genBaseOts(OtReceiver& base, PRNG& prng, Channel& chl)
//{
//
//    CpChannel s(chl);
//    auto ec = eval(genBaseOts(base, prng, s));
//    if (ec)
//        throw std::system_error(ec);
//}
//
namespace primihub::crypto {
void OtExtReceiver::genBaseOts(PRNG &prng, std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, &prng, &chl, base = DefaultBaseOT{});
  DefaultBaseOT base{};
  genBaseOts(base, prng, chl);
}

void OtExtReceiver::genBaseOts(OtSender &base, PRNG &prng,
                               std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, &, count = baseOtCount(),
  //         msgs = std::vector<std::array<block, 2>>{});
  u64 count = baseOtCount();
  std::vector<std::array<block, 2>> msgs{};

  msgs.resize(count);

  // MC_AWAIT(base.send(msgs, prng, chl));
  base.send(msgs, prng, chl);
  setBaseOts(msgs);
}

void OtExtSender::genBaseOts(PRNG &prng, std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, &, base = DefaultBaseOT{});
  DefaultBaseOT base{};
  genBaseOts(base, prng, chl);
}

void OtExtSender::genBaseOts(OtReceiver &base, PRNG &prng,
                             std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, &, count = baseOtCount(), msgs = std::vector<block>{},
  //          bv = BitVector{});
  u64 count = baseOtCount();
  std::vector<block> msgs{};
  BitVector bv{};

  msgs.resize(count);
  bv.resize(count);
  bv.randomize(prng);

  base.receive(bv, msgs, prng, chl);
  setBaseOts(msgs, bv);
}
} // namespace primihub::crypto
