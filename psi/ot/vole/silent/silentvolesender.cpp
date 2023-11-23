#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <optional>

#include "psi/ot/base/baseot.h"
#include "psi/ot/tools/tools.h"
#include "psi/ot/twochooseone/iknp/iknpotextsender.h"
#include "psi/ot/twochooseone/silent/silentotextreceiver.h"
#include "psi/ot/vole/noisy/noisyvolesender.h"
#include "psi/ot/vole/silent/silentvolesender.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;

u64 SilentVoleSender::baseOtCount() const { return mOtExtSender.baseOtCount(); }

bool SilentVoleSender::hasBaseOts() const { return mOtExtSender.hasBaseOts(); }

// sets the soft spoken base OTs that are then used to extend
void SilentVoleSender::setBaseOts(span<block> baseRecvOts,
                                  const BitVector &choices) {
  mOtExtSender.setBaseOts(baseRecvOts, choices);
}

void SilentVoleSender::genSilentBaseOts(PRNG &prng,
                                        std::shared_ptr<Channel> chl,
                                        std::optional<block> delta) {
  using BaseOT = DefaultBaseOT;

  // MC_BEGIN(task<>, this, delta, &prng, &chl,
  //          msg = AlignedUnVector<std::array<block, 2>>(silentBaseOtCount()),
  //          baseOt = BaseOT{}, prng2 = std::move(PRNG{}), xx = BitVector{},
  //          chl2 = Socket{}, nv = NoisyVoleSender{},
  //          noiseDeltaShares = std::vector<block>{});
  AlignedUnVector<std::array<block, 2>> msg(silentBaseOtCount());
  BaseOT baseOt{};
  PRNG prng2 = std::move(PRNG{});
  BitVector xx{};
  std::shared_ptr<Channel> chl2 = nullptr;
  NoisyVoleSender nv{};
  std::vector<block> noiseDeltaShares{};

  setTimePoint("SilentVoleSender.genSilent.begin");

  if (isConfigured() == false)
    throw std::runtime_error("configure must be called first");

  delta = delta.value_or(prng.get<block>());
  xx.append(delta->data(), 128);

  // compute the correlation for the noisy coordinates.
  noiseDeltaShares.resize(baseVoleCount());

  if (mBaseType == SilentBaseType::BaseExtend) {
    if (mOtExtRecver.hasBaseOts() == false) {
      msg.resize(msg.size() + mOtExtRecver.baseOtCount());
      // MC_AWAIT(mOtExtSender.send(msg, prng, chl));
      mOtExtSender.send(msg, prng, chl);

      mOtExtRecver.setBaseOts(span<std::array<block, 2>>(msg).subspan(
          msg.size() - mOtExtRecver.baseOtCount(), mOtExtRecver.baseOtCount()));
      msg.resize(msg.size() - mOtExtRecver.baseOtCount());

      // MC_AWAIT(nv.send(*delta, noiseDeltaShares, prng, mOtExtRecver, chl));
      nv.send(*delta, noiseDeltaShares, prng, mOtExtRecver, chl);
    } else {
      chl2 = chl->fork();
      prng2.SetSeed(prng.get());

      // MC_AWAIT(macoro::when_all_ready(
      //     nv.send(*delta, noiseDeltaShares, prng2, mOtExtRecver, chl2),
      //     mOtExtSender.send(msg, prng, chl)));
      auto send_fn1 = [this, &nv, &delta, &noiseDeltaShares, &prng2, chl2]() {
        nv.send(*delta, noiseDeltaShares, prng2, mOtExtRecver, chl2);
      };

      auto send_fn2 = [this, &msg, &prng, chl]() {
        mOtExtSender.send(msg, prng, chl);
      };

      auto fut1 = std::async(send_fn1);
      auto fut2 = std::async(send_fn2);
      fut1.get();
      fut2.get();
    }
  } else {
    chl2 = chl->fork();
    prng2.SetSeed(prng.get());
    // MC_AWAIT(macoro::when_all_ready(
    //     nv.send(*delta, noiseDeltaShares, prng2, baseOt, chl2),
    //     baseOt.send(msg, prng, chl)));
    auto send_fn1 = [&nv, &delta, &noiseDeltaShares, &prng2, &baseOt, chl2]() {
      nv.send(*delta, noiseDeltaShares, prng2, baseOt, chl2);
    };

    auto send_fn2 = [&baseOt, &msg, &prng, chl]() {
      baseOt.send(msg, prng, chl);
    };

    auto fut1 = std::async(send_fn1);
    auto fut2 = std::async(send_fn2);
    fut1.get();
    fut2.get();
  }

  setSilentBaseOts(msg, noiseDeltaShares);
  setTimePoint("SilentVoleSender.genSilent.done");
}

u64 SilentVoleSender::silentBaseOtCount() const {
  if (isConfigured() == false)
    throw std::runtime_error("configure must be called first");

  return mGen.baseOtCount() + mGapOts.size();
}

void SilentVoleSender::setSilentBaseOts(span<std::array<block, 2>> sendBaseOts,
                                        span<block> noiseDeltaShares) {
  if ((u64)sendBaseOts.size() != silentBaseOtCount())
    throw RTE_LOC;

  if (noiseDeltaShares.size() != baseVoleCount())
    throw RTE_LOC;

  auto genOt = sendBaseOts.subspan(0, mGen.baseOtCount());
  auto gapOt = sendBaseOts.subspan(genOt.size(), mGapOts.size());

  mGen.setBase(genOt);
  std::copy(gapOt.begin(), gapOt.end(), mGapOts.begin());
  mNoiseDeltaShares.resize(noiseDeltaShares.size());
  std::copy(noiseDeltaShares.begin(), noiseDeltaShares.end(),
            mNoiseDeltaShares.begin());
}

void SilverConfigure(u64 numOTs, u64 secParam, MultType mMultType,
                     u64 &mRequestedNumOTs, u64 &mNumPartitions, u64 &mSizePer,
                     u64 &mN2, u64 &mN, u64 &gap, SilverEncoder &mEncoder);

void SilentVoleSender::configure(u64 numOTs, SilentBaseType type,
                                 u64 secParam) {
  mBaseType = type;
  u64 gap = 0;

  switch (mMultType) {
  case MultType::slv5:
  case MultType::slv11:
    SilverConfigure(numOTs, secParam, mMultType, mRequestedNumOTs,
                    mNumPartitions, mSizePer, mN2, mN, gap, mEncoder);
    break;
  default:
    LOG(ERROR) << "Only support multtype slv5 and slv11.";
    throw std::runtime_error("Only support multtype slv5 and slv11.");
    break;
  }

  mGapOts.resize(gap);
  mGen.configure(mSizePer, mNumPartitions);

  mState = State::Configured;
}

// sigma = 0   Receiver
//
//    u_i is the choice bit
//    v_i = w_i + u_i * x
//
//    ------------------------ -
//    u' =   0000001000000000001000000000100000...00000,   u_i = 1 iff i \in S
//
//    v' = r + (x . u') = DPF(k0)
//       = r + (000000x00000000000x000000000x00000...00000)
//
//    u = u' * H             bit-vector * H. Mapping n'->n bits
//    v = v' * H		   block-vector * H. Mapping n'->n block
//
// sigma = 1   Sender
//
//    x   is the delta
//    w_i is the zero message
//
//    m_i0 = w_i
//    m_i1 = w_i + x
//
//    ------------------------
//    x
//    r = DPF(k1)
//
//    w = r * H

void SilentVoleSender::checkRT(std::shared_ptr<Channel> chl,
                               block delta) const {
  // MC_BEGIN(task<>, this, &chl, delta);
  // MC_AWAIT(chl.send(delta));
  // MC_AWAIT(chl.send(mB));
  // MC_AWAIT(chl.send(mNoiseDeltaShares));
  {
    auto status = chl->asyncSend(delta);
    if (!status.IsOK()) {
      LOG(ERROR) << "Send delta failed.";
      throw std::runtime_error("Send delta failed.");
    }
  }

  {
    auto status = chl->asyncSend(mB);
    if (!status.IsOK()) {
      LOG(ERROR) << "Send mB failed.";
      throw std::runtime_error("Send mB failed.");
    }
  }

  {
    auto status = chl->asyncSend(mNoiseDeltaShares);
    if (!status.IsOK()) {
      LOG(ERROR) << "Send mNoiseDeltaShares failed.";
      throw std::runtime_error("Send mNoiseDeltaShares failed.");
    }
  }
}

void SilentVoleSender::clear() {
  mB = {};
  mGen.clear();
}

void SilentVoleSender::silentSend(block delta, span<block> b, PRNG &prng,
                                  std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, delta, b, &prng, &chl);

  // MC_AWAIT(silentSendInplace(delta, b.size(), prng, chl));
  silentSendInplace(delta, b.size(), prng, chl);

  std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
  clear();

  setTimePoint("SilentVoleSender.expand.ldpc.msgCpy");
}

void SilentVoleSender::silentSendInplace(block delta, u64 n, PRNG &prng,
                                         std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, delta, n, &prng, &chl, gapVals =
  // std::vector<block>{},
  //          deltaShare = block{}, X = block{}, hash = std::array<u8, 32>{},
  //          noiseShares = span<block>{}, mbb = span<block>{});
  std::vector<block> gapVals{};
  block deltaShare{};
  block X{};
  std::array<u8, 32> hash{};
  span<block> noiseShares{};
  span<block> mbb{};

  setTimePoint("SilentVoleSender.ot.enter");

  if (isConfigured() == false) {
    // first generate 128 normal base OTs
    configure(n, SilentBaseType::BaseExtend);
  }

  if (mRequestedNumOTs != n)
    throw std::invalid_argument("n does not match the requested number of OTs "
                                "via configure(...). " LOCATION);

  if (mGen.hasBaseOts() == false) {
    // recvs data
    // MC_AWAIT(genSilentBaseOts(prng, chl, delta));
    genSilentBaseOts(prng, chl, delta);
  }

  // mDelta = delta;

  setTimePoint("SilentVoleSender.start");
  // gTimer.setTimePoint("SilentVoleSender.iknp.base2");

  if (mMalType == SilentSecType::Malicious) {
    deltaShare = mNoiseDeltaShares.back();
    mNoiseDeltaShares.pop_back();
  }

  // allocate B
  mB.resize(0);
  mB.resize(mN2);

  // derandomize the random OTs for the gap
  // to have the desired correlation.
  gapVals.resize(mGapOts.size());
  for (u64 i = mNumPartitions * mSizePer, j = 0; i < mN2; ++i, ++j) {
    auto v = mGapOts[j][0] ^ mNoiseDeltaShares[mNumPartitions + j];
    gapVals[j] = AES(mGapOts[j][1]).ecbEncBlock(ZeroBlock) ^ v;
    mB[i] = mGapOts[j][0];
  }

  if (gapVals.size()) {
    // MC_AWAIT(chl.send(std::move(gapVals)));
    auto status = chl->asyncSend(std::move(gapVals));
    if (!status.IsOK()) {
      LOG(ERROR) << "Send gapVals failed.";
      throw std::runtime_error("Send gapVals failed.");
    }
  }

  if (mTimer)
    mGen.setTimer(*mTimer);

  // program the output the PPRF to be secret shares of
  // our secret share of delta * noiseVals. The receiver
  // can then manually add their shares of this to the
  // output of the PPRF at the correct locations.
  noiseShares = span<block>(mNoiseDeltaShares.data(), mNumPartitions);
  mbb = mB.subspan(0, mNumPartitions * mSizePer);
  // MC_AWAIT(mGen.expand(chl, noiseShares, prng, mbb,
  //                      PprfOutputFormat::Interleaved, true, mNumThreads));
  mGen.expand(chl, noiseShares, prng, mbb, PprfOutputFormat::Interleaved, true,
              mNumThreads);

  setTimePoint("SilentVoleSender.expand.pprf_transpose");
  if (mDebug) {
    // MC_AWAIT(checkRT(chl, delta));
    checkRT(chl, delta);
    setTimePoint("SilentVoleSender.expand.checkRT");
  }

  if (mMalType == SilentSecType::Malicious) {
    // MC_AWAIT(chl.recv(X));
    auto fut = chl->asyncRecv(X);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv X failed.";
      throw std::runtime_error("Recv X failed.");
    }

    hash = ferretMalCheck(X, deltaShare);

    // MC_AWAIT(chl.send(std::move(hash)));
    status = chl->asyncSend(std::move(hash));
    if (!status.IsOK()) {
      LOG(ERROR) << "Send hash failed.";
      throw std::runtime_error("Send hash failed.");
    }
  }

  switch (mMultType) {
  case MultType::slv5:
  case MultType::slv11:
    if (mTimer)
      mEncoder.setTimer(getTimer());

    mEncoder.dualEncode<block>(mB);
    setTimePoint("SilentVoleSender.expand.Silver");
    break;
  default:
    LOG(ERROR) << "Only support multtype slv5 and slv11.";
    throw std::runtime_error("Only support multtype slv5 and slv11.");
    break;
  }

  mB.resize(mRequestedNumOTs);

  mState = State::Default;
  mNoiseDeltaShares.clear();
}

std::array<u8, 32> SilentVoleSender::ferretMalCheck(block X, block deltaShare) {

  auto xx = X;
  block sum0 = ZeroBlock;
  block sum1 = ZeroBlock;
  for (u64 i = 0; i < (u64)mB.size(); ++i) {
    block low, high;
    xx.gf128Mul(mB[i], low, high);
    sum0 = sum0 ^ low;
    sum1 = sum1 ^ high;

    xx = xx.gf128Mul(X);
  }

  block mySum = sum0.gf128Reduce(sum1);

  std::array<u8, 32> myHash;
  RandomOracle ro(32);
  ro.Update(mySum ^ deltaShare);
  ro.Final(myHash);

  return myHash;
  // chl.send(myHash);
}
} // namespace primihub::crypto
