#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "psi/ot/base/baseot.h"
#include "psi/ot/vole/noisy/noisyvolereceiver.h"
#include "psi/ot/vole/silent/silentvolereceiver.h"
#include "psi/ot/vole/silent/silentvolesender.h"

#include <time.h>
#include <iostream>

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;

u64 getPartitions(u64 scaler, u64 p, u64 secParam);

// sets the Iknp base OTs that are then used to extend
void SilentVoleReceiver::setBaseOts(span<std::array<block, 2>> baseSendOts) {
  mOtExtRecver.setBaseOts(baseSendOts);
}

// return the number of base OTs soft spoken needs
u64 SilentVoleReceiver::baseOtCount() const {
  return mOtExtRecver.baseOtCount();
}

// returns true if the soft spoken base OTs are currently set.
bool SilentVoleReceiver::hasBaseOts() const {
  return mOtExtRecver.hasBaseOts();
};

BitVector SilentVoleReceiver::sampleBaseChoiceBits(PRNG &prng) {

  if (isConfigured() == false)
    throw std::runtime_error("configure(...) must be called first");

  auto choice = mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);

  mGapBaseChoice.resize(mGapOts.size());
  mGapBaseChoice.randomize(prng);
  choice.append(mGapBaseChoice);

  return choice;
}

std::vector<block> SilentVoleReceiver::sampleBaseVoleVals(PRNG &prng) {
  if (isConfigured() == false)
    throw RTE_LOC;
  if (mGapBaseChoice.size() != mGapOts.size())
    throw std::runtime_error("sampleBaseChoiceBits must be called before "
                             "sampleBaseVoleVals. " LOCATION);

  // sample the values of the noisy coordinate of c
  // and perform a noicy vole to get x+y = mD * c
  auto w = mNumPartitions + mGapOts.size();
  // std::vector<block> y(w);
  mNoiseValues.resize(w);
  prng.get<block>(mNoiseValues);

  mS.resize(mNumPartitions);
  mGen.getPoints(mS, getPprfFormat());

  auto j = mNumPartitions * mSizePer;

  for (u64 i = 0; i < (u64)mGapBaseChoice.size(); ++i) {
    if (mGapBaseChoice[i]) {
      mS.push_back(j + i);
    }
  }

  if (mMalType == SilentSecType::Malicious) {

    mMalCheckSeed = prng.get();
    mMalCheckX = ZeroBlock;
    auto yIter = mNoiseValues.begin();

    for (u64 i = 0; i < mNumPartitions; ++i) {
      auto s = mS[i];
      auto xs = mMalCheckSeed.gf128Pow(s + 1);
      mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
      ++yIter;
    }

    auto sIter = mS.begin() + mNumPartitions;
    for (u64 i = 0; i < mGapBaseChoice.size(); ++i) {
      if (mGapBaseChoice[i]) {
        auto s = *sIter;
        auto xs = mMalCheckSeed.gf128Pow(s + 1);
        mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
        ++sIter;
      }
      ++yIter;
    }

    std::vector<block> y(mNoiseValues.begin(), mNoiseValues.end());
    y.push_back(mMalCheckX);
    return y;
  }

  return std::vector<block>(mNoiseValues.begin(), mNoiseValues.end());
}

void SilentVoleReceiver::genBaseOts(PRNG &prng,
                                    std::shared_ptr<Channel> chl) {
  return mOtExtRecver.genBaseOts(prng, chl);
  // mIknpSender.genBaseOts(mIknpRecver, prng, chl);
}

void SilverConfigure(u64 numOTs, u64 secParam, MultType mMultType,
                     u64 &mRequestedNumOTs, u64 &mNumPartitions, u64 &mSizePer,
                     u64 &mN2, u64 &mN, u64 &gap, SilverEncoder &mEncoder);

void SilentVoleReceiver::configure(u64 numOTs, SilentBaseType type,
                                   u64 secParam) {
  mState = State::Configured;
  u64 gap = 0;
  mBaseType = type;

  switch (mMultType) {
  case MultType::slv5:
  case MultType::slv11:

    SilverConfigure(numOTs, secParam, mMultType, mRequestedNumOTs,
                    mNumPartitions, mSizePer, mN2, mN, gap, mEncoder);

    break;
  default:
    throw std::runtime_error("Only support multtype slv5 and slv11.");
    break;
  }

  mGapOts.resize(gap);
  mGen.configure(mSizePer, mNumPartitions);
}

void SilentVoleReceiver::genSilentBaseOts(PRNG &prng,
                                          std::shared_ptr<Channel> chl) {
  using BaseOT = DefaultBaseOT;

  // MC_BEGIN(task<>, this, &prng, &chl, choice = BitVector{}, bb = BitVector{},
  //          msg = AlignedUnVector<block>{}, baseVole = std::vector<block>{},
  //          baseOt = BaseOT{}, chl2 = Socket{}, prng2 = std::move(PRNG{}),
  //          noiseVals = std::vector<block>{},
  //          noiseDeltaShares = std::vector<block>{}, nv = NoisyVoleReceiver{}
  // );
  BitVector choice{};
  BitVector bb{};
  AlignedUnVector<block> msg{};
  std::vector<block> baseVole{};
  BaseOT baseOt{};
  std::shared_ptr<Channel> chl2 = nullptr;
  PRNG prng2 = std::move(PRNG{});
  std::vector<block> noiseVals{};
  std::vector<block> noiseDeltaShares{};
  NoisyVoleReceiver nv{};

  setTimePoint("SilentVoleReceiver.genSilent.begin");
  if (isConfigured() == false)
    throw std::runtime_error("configure must be called first");

  choice = sampleBaseChoiceBits(prng);
  msg.resize(choice.size());

  // sample the noise vector noiseVals such that we will compute
  //
  //  C = (000 noiseVals[0] 0000 ... 000 noiseVals[p] 000)
  //
  // and then we want secret shares of C * delta. As a first step
  // we will compute secret shares of
  //
  // delta * noiseVals
  //
  // and store our share in voleDeltaShares. This party will then
  // compute their share of delta * C as what comes out of the PPRF
  // plus voleDeltaShares[i] added to the appreciate spot. Similarly, the
  // other party will program the PPRF to output their share of delta *
  // noiseVals.
  //
  noiseVals = sampleBaseVoleVals(prng);
  noiseDeltaShares.resize(noiseVals.size());
  if (mTimer)
    nv.setTimer(*mTimer);

  if (mBaseType == SilentBaseType::BaseExtend) {
    if (mOtExtSender.hasBaseOts() == false) {
      msg.resize(msg.size() + mOtExtSender.baseOtCount());
      bb.resize(mOtExtSender.baseOtCount());
      bb.randomize(prng);
      choice.append(bb);

      // MC_AWAIT(mOtExtRecver.receive(choice, msg, prng, chl));
      mOtExtRecver.receive(choice, msg, prng, chl);

      mOtExtSender.setBaseOts(
          span<block>(msg).subspan(msg.size() - mOtExtSender.baseOtCount(),
                                   mOtExtSender.baseOtCount()),
          bb);

      msg.resize(msg.size() - mOtExtSender.baseOtCount());
      // MC_AWAIT(
      //     nv.receive(noiseVals, noiseDeltaShares, prng, mOtExtSender, chl));
      nv.receive(noiseVals, noiseDeltaShares, prng, mOtExtSender, chl);
    } else {
      chl2 = chl->fork();
      prng2.SetSeed(prng.get());

      // MC_AWAIT(macoro::when_all_ready(
      //     nv.receive(noiseVals, noiseDeltaShares, prng2, mOtExtSender, chl2),
      //     mOtExtRecver.receive(choice, msg, prng, chl)));
      auto recv_fn1 = [this, &nv, &noiseVals, &noiseDeltaShares, &prng2,
                       chl2]() {
        nv.receive(noiseVals, noiseDeltaShares, prng2, mOtExtSender, chl2);
      };

      auto recv_fn2 = [this, &choice, &msg, &prng, chl]() {
        mOtExtRecver.receive(choice, msg, prng, chl);
      };

      auto recv_fut1 = std::async(recv_fn1);
      auto recv_fut2 = std::async(recv_fn2);
      recv_fut1.get();
      recv_fut2.get();
    }
  } else {
    chl2 = chl->fork();
    prng2.SetSeed(prng.get());

    // MC_AWAIT(macoro::when_all_ready(
    //     nv.receive(noiseVals, noiseDeltaShares, prng2, baseOt, chl2),
    //     baseOt.receive(choice, msg, prng, chl)));
    auto recv_fn1 = [&nv, &noiseVals, &noiseDeltaShares, &prng2, &baseOt,
                     chl2]() {
      nv.receive(noiseVals, noiseDeltaShares, prng2, baseOt, chl2);
    };

    auto recv_fn2 = [&baseOt, &choice, &msg, &prng, chl]() {
      baseOt.receive(choice, msg, prng, chl);
    };

    auto recv_fut1 = std::async(recv_fn1);
    auto recv_fut2 = std::async(recv_fn2);
    recv_fut1.get();
    recv_fut2.get();
  }

  setSilentBaseOts(msg, noiseDeltaShares);

  setTimePoint("SilentVoleReceiver.genSilent.done");
};

void SilentVoleReceiver::setSilentBaseOts(span<block> recvBaseOts,
                                          span<block> noiseDeltaShare) {
  if (isConfigured() == false)
    throw std::runtime_error("configure(...) must be called first.");

  if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
    throw std::runtime_error("wrong number of silent base OTs");

  auto genOts = recvBaseOts.subspan(0, mGen.baseOtCount());
  auto gapOts = recvBaseOts.subspan(mGen.baseOtCount(), mGapOts.size());

  mGen.setBase(genOts);
  std::copy(gapOts.begin(), gapOts.end(), mGapOts.begin());

  if (mMalType == SilentSecType::Malicious) {
    mDeltaShare = noiseDeltaShare.back();
    noiseDeltaShare = noiseDeltaShare.subspan(0, noiseDeltaShare.size() - 1);
  }

  mNoiseDeltaShare =
      AlignedVector<block>(noiseDeltaShare.begin(), noiseDeltaShare.end());

  mState = State::HasBase;
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
void SilentVoleReceiver::silentReceive(span<block> c, span<block> b, PRNG &prng,
                                       std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, c, b, &prng, &chl);
  if (c.size() != b.size())
    throw RTE_LOC;

  // MC_AWAIT(silentReceiveInplace(c.size(), prng, chl));
  silentReceiveInplace(c.size(), prng, chl);

  std::memcpy(c.data(), mC.data(), c.size() * sizeof(block));
  std::memcpy(b.data(), mA.data(), b.size() * sizeof(block));
  clear();
}

void SilentVoleReceiver::silentReceiveInplace(
    u64 n, PRNG &prng, std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, n, &prng, &chl, gapVals = std::vector<block>{},
  //          myHash = std::array<u8, 32>{}, theirHash = std::array<u8, 32>{}
  // );
  std::vector<block> gapVals{};
  std::array<u8, 32> myHash{};
  std::array<u8, 32> theirHash{};
  std::clock_t start;
  std::clock_t end;
  gTimer.setTimePoint("SilentVoleReceiver.ot.enter");

  if (isConfigured() == false) {
    // first generate 128 normal base OTs
    configure(n, SilentBaseType::BaseExtend);
  }

  if (mRequestedNumOTs != n)
    throw std::invalid_argument("n does not match the requested number of OTs "
                                "via configure(...). " LOCATION);

  if (hasSilentBaseOts() == false) {
    genSilentBaseOts(prng, chl);
  }

  // allocate mA
  mA.resize(0);
  mA.resize(mN2);

  setTimePoint("SilentVoleReceiver.alloc");

  // allocate the space for mC
  mC.resize(0);
  mC.resize(mN2, AllocType::Zeroed);
  setTimePoint("SilentVoleReceiver.alloc.zero");

  // derandomize the random OTs for the gap
  // to have the desired correlation.
  gapVals.resize(mGapOts.size());

  if (gapVals.size()) {
    // MC_AWAIT(chl.recv(gapVals));
    auto fut = chl->asyncRecv(gapVals);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv gapVals failed.";
      throw std::runtime_error("Recv gapVals failed.");
    }
  }

  for (auto g : rng(mGapOts.size())) {
    auto aa = mA.subspan(mNumPartitions * mSizePer);
    auto cc = mC.subspan(mNumPartitions * mSizePer);

    auto noise = mNoiseValues.subspan(mNumPartitions);
    auto noiseShares = mNoiseDeltaShare.subspan(mNumPartitions);

    if (mGapBaseChoice[g]) {
      cc[g] = noise[g];
      aa[g] =
          AES(mGapOts[g]).ecbEncBlock(ZeroBlock) ^ gapVals[g] ^ noiseShares[g];
    } else
      aa[g] = mGapOts[g];
  }

  setTimePoint("SilentVoleReceiver.recvGap");

  if (mTimer)
    mGen.setTimer(*mTimer);
  // expand the seeds into mA
  // MC_AWAIT(mGen.expand(chl, prng, mA.subspan(0, mNumPartitions * mSizePer),
  //                      PprfOutputFormat::Interleaved, true, mNumThreads));
  mGen.expand(chl, prng, mA.subspan(0, mNumPartitions * mSizePer),
              PprfOutputFormat::Interleaved, true, mNumThreads);

  setTimePoint("SilentVoleReceiver.expand.pprf_transpose");

  // populate the noisy coordinates of mC and
  // update mA to be a secret share of mC * delta
  for (u64 i = 0; i < mNumPartitions; ++i) {
    auto pnt = mS[i];
    mC[pnt] = mNoiseValues[i];
    mA[pnt] = mA[pnt] ^ mNoiseDeltaShare[i];
  }

  if (mDebug) {
    // MC_AWAIT(checkRT(chl));
    checkRT(chl);
    setTimePoint("SilentVoleReceiver.expand.checkRT");
  }

  if (mMalType == SilentSecType::Malicious) {
    // MC_AWAIT(chl.send(std::move(mMalCheckSeed)));
    {
      auto status = chl->asyncSend(std::move(mMalCheckSeed));
      if (!status.IsOK()) {
        LOG(ERROR) << "Send mMalCheckSeed failed.";
        throw std::runtime_error("Send mMalCheckSeed failed.");
      }
    }

    myHash = ferretMalCheck(mDeltaShare, mNoiseValues);

    // MC_AWAIT(chl.recv(theirHash));
    {
      auto fut = chl->asyncRecv(theirHash);
      auto status = fut.get();
      if (!status.IsOK()) {
        LOG(ERROR) << "Recv theirHash failed.";
        throw std::runtime_error("Recv theirHash failed.");
      }
    }

    if (theirHash != myHash)
      throw RTE_LOC;
  }
  start = clock();
  switch (mMultType) {
  case MultType::slv5:
  case MultType::slv11:
    if (mTimer)
      mEncoder.setTimer(getTimer());

    // compress both mA and mC in place.
    mEncoder.dualEncode2<block, block>(mA, mC);
    setTimePoint("SilentVoleReceiver.expand.cirTransEncode.a");
    break;
  default:
    throw std::runtime_error("Only support multtype slv5 and slv11.");
    break;
  }
  end = clock();
  std::cout << "MultType encode in silentvole" << "cost " << (double)(end - start) / CLOCKS_PER_SEC << "sec." << std::endl;

  // resize the buffers down to only contain the real elements.
  mA.resize(mRequestedNumOTs);
  mC.resize(mRequestedNumOTs);

  mNoiseValues = {};
  mNoiseDeltaShare = {};

  // make the protocol as done and that
  // mA,mC are ready to be consumed.
  mState = State::Default;
}

std::array<u8, 32> SilentVoleReceiver::ferretMalCheck(block deltaShare,
                                                      span<block> yy) {

  block xx = mMalCheckSeed;
  block sum0 = ZeroBlock;
  block sum1 = ZeroBlock;

  for (u64 i = 0; i < (u64)mA.size(); ++i) {
    block low, high;
    xx.gf128Mul(mA[i], low, high);
    sum0 = sum0 ^ low;
    sum1 = sum1 ^ high;
    // mySum = mySum ^ xx.gf128Mul(mA[i]);

    // xx = mMalCheckSeed^{i+1}
    xx = xx.gf128Mul(mMalCheckSeed);
  }
  block mySum = sum0.gf128Reduce(sum1);

  std::array<u8, 32> myHash;
  RandomOracle ro(32);
  ro.Update(mySum ^ deltaShare);
  ro.Final(myHash);
  return myHash;
}

u64 SilentVoleReceiver::silentBaseOtCount() const {
  if (isConfigured() == false)
    throw std::runtime_error("configure must be called first");

  return mGen.baseOtCount() + mGapOts.size();
}

void SilentVoleReceiver::checkRT(std::shared_ptr<Channel> chl) const {
  // MC_BEGIN(task<>, this, &chl, B = AlignedVector<block>(mA.size()),
  //          sparseNoiseDelta = std::vector<block>(mA.size()),
  //          noiseDeltaShare2 = std::vector<block>(), delta = block{});
  AlignedVector<block> B(mA.size());
  std::vector<block> sparseNoiseDelta(mA.size());
  std::vector<block> noiseDeltaShare2{};
  std::vector<block> mB(mA.size());
  block delta{};

  // MC_AWAIT(chl.recv(delta));
  // MC_AWAIT(chl.recv(B));
  // MC_AWAIT(chl.recvResize(noiseDeltaShare2));
  {
    auto fut = chl->asyncRecv(delta);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv delta failed.";
      throw std::runtime_error("Recv delta failed.");
    }
  }

  {
    auto fut = chl->asyncRecv(B);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv B failed.";
      throw std::runtime_error("Recv B failed.");
    }
  }

  {
    auto fut = chl->asyncRecv(noiseDeltaShare2);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv noiseDeltaShare2 failed.";
      throw std::runtime_error("Recv noiseDeltaShare2 failed.");
    }
  }

  // check that at locations  mS[0],...,mS[..]
  // that we hold a sharing mA, mB of
  //
  //  delta * mC = delta * (00000 noiseDeltaShare2[0] 0000 .... 0000
  //  noiseDeltaShare2[m] 0000)
  //
  // where noiseDeltaShare2[i] is at position mS[i] of mC
  //
  // That is, I hold mA, mC s.t.
  //
  //  delta * mC = mA + mB
  //

  if (noiseDeltaShare2.size() != mNoiseDeltaShare.size())
    throw RTE_LOC;

  for (auto i : rng(mNoiseDeltaShare.size())) {
    if ((mNoiseDeltaShare[i] ^ noiseDeltaShare2[i]) !=
        mNoiseValues[i].gf128Mul(delta))
      throw RTE_LOC;
  }

  {
    for (auto i : rng(mNumPartitions * mSizePer)) {
      auto iter = std::find(mS.begin(), mS.end(), i);
      if (iter != mS.end()) {
        auto d = iter - mS.begin();

        if (mC[i] != mNoiseValues[d])
          throw RTE_LOC;

        if (mNoiseValues[d].gf128Mul(delta) != (mA[i] ^ B[i])) {
          std::cout
              << "bad vole base correlation, mA[i] + mB[i] != mC[i] * delta"
              << std::endl;
          std::cout << "i     " << i << std::endl;
          std::cout << "mA[i] " << mA[i] << std::endl;
          std::cout << "mB[i] " << B[i] << std::endl;
          std::cout << "mC[i] " << mC[i] << std::endl;
          std::cout << "delta " << delta << std::endl;
          std::cout << "mA[i] + mB[i] " << (mA[i] ^ B[i]) << std::endl;
          std::cout << "mC[i] * delta " << (mC[i].gf128Mul(delta)) << std::endl;

          throw RTE_LOC;
        }
      } else {
        if (mA[i] != B[i]) {
          std::cout << mA[i] << " " << B[i] << std::endl;
          throw RTE_LOC;
        }

        if (mC[i] != oc::ZeroBlock)
          throw RTE_LOC;
      }
    }

    u64 d = mNumPartitions;
    for (auto j : rng(mGapBaseChoice.size())) {
      auto idx = j + mNumPartitions * mSizePer;
      auto aa = mA.subspan(mNumPartitions * mSizePer);
      auto bb = B.subspan(mNumPartitions * mSizePer);
      auto cc = mC.subspan(mNumPartitions * mSizePer);
      auto noise = mNoiseValues.subspan(mNumPartitions);
      // auto noiseShare = mNoiseValues.subspan(mNumPartitions);
      if (mGapBaseChoice[j]) {
        if (mS[d++] != idx)
          throw RTE_LOC;

        if (cc[j] != noise[j]) {
          std::cout << "sparse noise vector mC is not the expected value"
                    << std::endl;
          std::cout << "i j      " << idx << " " << j << std::endl;
          std::cout << "mC[i]    " << cc[j] << std::endl;
          std::cout << "noise[j] " << noise[j] << std::endl;
          throw RTE_LOC;
        }

        if (noise[j].gf128Mul(delta) != (aa[j] ^ bb[j])) {

          std::cout
              << "bad vole base GAP correlation, mA[i] + mB[i] != mC[i] * delta"
              << std::endl;
          std::cout << "i     " << idx << std::endl;
          std::cout << "mA[i] " << aa[j] << std::endl;
          std::cout << "mB[i] " << bb[j] << std::endl;
          std::cout << "mC[i] " << cc[j] << std::endl;
          std::cout << "delta " << delta << std::endl;
          std::cout << "mA[i] + mB[i] " << (aa[j] ^ bb[j]) << std::endl;
          std::cout << "mC[i] * delta " << (cc[j].gf128Mul(delta)) << std::endl;
          std::cout << "noise * delta " << (noise[j].gf128Mul(delta))
                    << std::endl;
          throw RTE_LOC;
        }

      } else {
        if (aa[j] != bb[j])
          throw RTE_LOC;

        if (cc[j] != oc::ZeroBlock)
          throw RTE_LOC;
      }
    }

    if (d != mS.size())
      throw RTE_LOC;
  }

  //{

  //	auto cDelta = B;
  //	for (u64 i = 0; i < cDelta.size(); ++i)
  //		cDelta[i] = cDelta[i] ^ mA[i];

  //	std::vector<block> exp(mN2);
  //	for (u64 i = 0; i < mNumPartitions; ++i)
  //	{
  //		auto j = mS[i];
  //		exp[j] = noiseDeltaShare2[i];
  //	}

  //	auto iter = mS.begin() + mNumPartitions;
  //	for (u64 i = 0, j = mNumPartitions * mSizePer; i < mGapOts.size(); ++i,
  //++j)
  //	{
  //		if (mGapBaseChoice[i])
  //		{
  //			if (*iter != j)
  //				throw RTE_LOC;
  //			++iter;

  //			exp[j] = noiseDeltaShare2[mNumPartitions + i];
  //		}
  //	}

  //	if (iter != mS.end())
  //		throw RTE_LOC;

  //	bool failed = false;
  //	for (u64 i = 0; i < mN2; ++i)
  //	{
  //		if (neq(cDelta[i], exp[i]))
  //		{
  //			std::cout << i << " / " << mN2 <<
  //				" cd = " << cDelta[i] <<
  //				" exp= " << exp[i] << std::endl;
  //			failed = true;
  //		}
  //	}

  //	if (failed)
  //		throw RTE_LOC;

  //	std::cout << "debug check ok" << std::endl;
  //}
}

void SilentVoleReceiver::clear() {
  mS = {};
  mA = {};
  mC = {};
  mGen.clear();
  mGapBaseChoice = {};
}

} // namespace primihub::crypto
