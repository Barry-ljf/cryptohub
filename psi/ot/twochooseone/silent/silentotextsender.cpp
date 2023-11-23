#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/ThreadBarrier.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <glog/logging.h>

#include "psi/ot/base/baseot.h"
#include "psi/ot/tools/tools.h"
#include "psi/ot/twochooseone/silent/silentotextreceiver.h"
#include "psi/ot/twochooseone/silent/silentotextsender.h"
#include "psi/ot/twochooseone/tcootdefines.h"
#include "psi/ot/vole/noisy/noisyvolereceiver.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;
// u64 secLevel(u64 scale, u64 n, u64 points)
//{
//    auto x1 = std::log2(scale * n / double(n));
//    auto x2 = std::log2(scale * n) / 2;
//    return static_cast<u64>(points * x1 + x2);
//}

// u64 getPartitions(u64 scaler, u64 n, u64 secParam)
//{
//    if (scaler < 2)
//        throw std::runtime_error("scaler must be 2 or greater");

//    u64 ret = 1;
//    auto ss = secLevel(scaler, n, ret);
//    while (ss < secParam)
//    {
//        ++ret;
//        ss = secLevel(scaler, n, ret);
//        if (ret > 1000)
//            throw std::runtime_error("failed to find silent OT parameters");
//    }
//    return roundUpTo(ret, 8);
//}

// We get e^{-2td} security against linear attacks,
// with noise weigh t and minDist d.
// For regular we can be slightly more accurate with
//    (1 − 2d)^t
// which implies a bit security level of
// k = -t * log2(1 - 2d)
// t = -k / log2(1 - 2d)
u64 getRegNoiseWeight(double minDistRatio, u64 secParam) {
  if (minDistRatio > 0.5 || minDistRatio <= 0)
    throw RTE_LOC;

  auto d = std::log2(1 - 2 * minDistRatio);
  auto t = std::max<u64>(128, -double(secParam) / d);

  return roundUpTo(t, 8);
}

bool gSilverWarning = true;
void SilverConfigure(u64 numOTs, u64 secParam, MultType mMultType,
                     u64 &mRequestedNumOTs, u64 &mNumPartitions, u64 &mSizePer,
                     u64 &mN2, u64 &mN, u64 &gap, SilverEncoder &mEncoder) {
#ifndef NO_SILVER_WARNING

  // warn the user on program exit.
  struct Warned {
    ~Warned() {
      if (gSilverWarning) {
        LOG(WARNING)
            << "WARNING: This program made use of the LPN silver encoder. "
            << "This encoder is experimental and should not be used in "
               "production.";
      }
    }
  };
  static Warned wardned;
#endif

  mRequestedNumOTs = numOTs;
  auto mScaler = 2;

  auto code =
      mMultType == MultType::slv11 ? SilverCode::Weight11 : SilverCode::Weight5;

  gap = SilverCode::gap(code);

  mNumPartitions = getRegNoiseWeight(0.2, secParam);
  mSizePer =
      roundUpTo((numOTs * mScaler + mNumPartitions - 1) / mNumPartitions, 8);
  mN2 = mSizePer * mNumPartitions + gap;
  mN = mN2 / mScaler;

  if (mN2 % mScaler)
    throw RTE_LOC;

  mEncoder.mL.init(mN, code);
  mEncoder.mR.init(mN, code, true);
}

// sets the KOS base OTs that are then used to extend
void SilentOtExtSender::setBaseOts(span<block> baseRecvOts,
                                   const BitVector &choices) {
  mOtExtSender.setBaseOts(baseRecvOts, choices);
}

// Returns an independent copy of this extender.
std::unique_ptr<OtExtSender> SilentOtExtSender::split() {
  auto ptr = new SilentOtExtSender;
  auto ret = std::unique_ptr<OtExtSender>(ptr);
  ptr->mOtExtSender = mOtExtSender.splitBase();
  return ret;
}

// use the default base OT class to generate the
// IKNP base OTs that are required.
void SilentOtExtSender::genBaseOts(PRNG &prng,
                                   std::shared_ptr<Channel> chl) {
  return mOtExtSender.genBaseOts(prng, chl);
}

u64 SilentOtExtSender::baseOtCount() const {
  return mOtExtSender.baseOtCount();
}

bool SilentOtExtSender::hasBaseOts() const { return mOtExtSender.hasBaseOts(); }

void SilentOtExtSender::genSilentBaseOts(PRNG &prng,
                                         std::shared_ptr<Channel> chl,
                                         bool useOtExtension) {
  // MC_BEGIN(task<>, this, &prng, &chl, useOtExtension,
  //          msg = AlignedUnVector<std::array<block, 2>>(silentBaseOtCount()),
  //          base = DefaultBaseOT{});
  AlignedUnVector<std::array<block, 2>> msg(silentBaseOtCount());
  DefaultBaseOT base{};

  if (isConfigured() == false)
    throw std::runtime_error("configure must be called first");

  // If we have IKNP base OTs, use them
  // to extend to get the silent base OTs.
  if (useOtExtension) {
    // mOtExtSender.mFiatShamir = true;
    // MC_AWAIT(mOtExtSender.send(msg, prng, chl));
    mOtExtSender.send(msg, prng, chl);
  } else {
    // otherwise just generate the silent
    // base OTs directly.
    // MC_AWAIT(base.send(msg, prng, chl));
    base.send(msg, prng, chl);
    setTimePoint("sender.gen.baseOT");
  }

  setSilentBaseOts(msg);
  setTimePoint("sender.gen.done");
}

u64 SilentOtExtSender::silentBaseOtCount() const {
  if (isConfigured() == false)
    throw std::runtime_error("configure must be called first");

  auto n = mGen.baseOtCount() + mGapOts.size();

  if (mMalType == SilentSecType::Malicious)
    n += 128;

  return n;
}

void SilentOtExtSender::setSilentBaseOts(
    span<std::array<block, 2>> sendBaseOts) {

  if ((u64)sendBaseOts.size() != silentBaseOtCount())
    throw RTE_LOC;

  auto genOt = sendBaseOts.subspan(0, mGen.baseOtCount());
  auto gapOt = sendBaseOts.subspan(genOt.size(), mGapOts.size());
  auto malOt = sendBaseOts.subspan(genOt.size() + gapOt.size());
  mMalCheckOts.resize((mMalType == SilentSecType::Malicious) * 128);

  mGen.setBase(genOt);
  std::copy(gapOt.begin(), gapOt.end(), mGapOts.begin());
  std::copy(malOt.begin(), malOt.end(), mMalCheckOts.begin());
}

void SilentOtExtSender::configure(u64 numOTs, u64 scaler, u64 numThreads,
                                  SilentSecType malType) {
  mMalType = malType;
  mNumThreads = numThreads;

  mGapOts.resize(0);

  switch (mMultType) {
  case MultType::slv5:
  case MultType::slv11: {
    if (scaler != 2)
      throw std::runtime_error(
          "only scaler = 2 is supported for slv. " LOCATION);

    u64 gap;
    SilverConfigure(numOTs, 128, mMultType, mRequestNumOts, mNumPartitions,
                    mSizePer, mN2, mN, gap, mEncoder);

    mGapOts.resize(gap);
    break;
  }
  default:
    LOG(ERROR) << "Only support multtype slv5 and slv11.";
    throw std::runtime_error("Only support multtype slv5 and slv11.");
    break;
  }

  mGen.configure(mSizePer, mNumPartitions);
}

void SilentOtExtSender::checkRT(std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, &chl);

  // MC_AWAIT(chl.send(mB));
  {
    auto status = chl->asyncSend(mB);
    if (!status.IsOK()) {
      LOG(ERROR) << "Send mB failed.";
      throw std::runtime_error("Send mB failed.");
    }
  }

  // MC_AWAIT(chl.send(mDelta));
  {
    auto status = chl->asyncSend(mDelta);
    if (!status.IsOK()) {
      LOG(ERROR) << "send mDelta failed.";
      throw std::runtime_error("send mDelta failed.");
    }
  }

  setTimePoint("sender.expand.checkRT");
}

void SilentOtExtSender::clear() {
  mN = 0;
  mN2 = 0;
  mRequestNumOts = 0;
  mSizePer = 0;
  mNumPartitions = 0;
  mP = 0;

  mB = {};

  mDelta = block(0, 0);

  mGapOts = {};

  mGen.clear();
}

void SilentOtExtSender::send(span<std::array<block, 2>> messages, PRNG &prng,
                             std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, messages, &prng, &chl,
  //          correction = BitVector(messages.size()), iter = BitIterator{},
  //          i = u64{});
  BitVector correction(messages.size());
  BitIterator iter{};
  u64 i{};

  // MC_AWAIT(silentSend(messages, prng, chl));
  silentSend(messages, prng, chl);

  // MC_AWAIT(chl.recv(correction));
  {
    auto fut = chl->asyncRecv(correction);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv correction failed.";
      std::runtime_error("Recv correction failed.");
    }
  }

  iter = correction.begin();

  for (i = 0; i < static_cast<u64>(messages.size()); ++i) {
    u8 bit = *iter;
    ++iter;
    auto temp = messages[i];
    messages[i][0] = temp[bit];
    messages[i][1] = temp[bit ^ 1];
  }
}

void SilentOtExtSender::silentSend(span<std::array<block, 2>> messages,
                                   PRNG &prng,
                                   std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, messages, &prng, &chl, type =
  // ChoiceBitPacking::True);
  ChoiceBitPacking type = ChoiceBitPacking::True;

  // MC_AWAIT(silentSendInplace(prng.get(), messages.size(), prng, chl));
  silentSendInplace(prng.get(), messages.size(), prng, chl);
  hash(messages, type);
  clear();
}

void SilentOtExtSender::hash(span<std::array<block, 2>> messages,
                             ChoiceBitPacking type) {
  if (type == ChoiceBitPacking::True) {

    block mask = OneBlock ^ AllOneBlock;
    auto d = mDelta & mask;

    auto n8 = (u64)messages.size() / 8 * 8;

    std::array<block, 2> *m = messages.data();
    auto r = mB.data();

    for (u64 i = 0; i < n8; i += 8) {

      r[0] = r[0] & mask;
      r[1] = r[1] & mask;
      r[2] = r[2] & mask;
      r[3] = r[3] & mask;
      r[4] = r[4] & mask;
      r[5] = r[5] & mask;
      r[6] = r[6] & mask;
      r[7] = r[7] & mask;

      m[0][0] = r[0];
      m[1][0] = r[1];
      m[2][0] = r[2];
      m[3][0] = r[3];
      m[4][0] = r[4];
      m[5][0] = r[5];
      m[6][0] = r[6];
      m[7][0] = r[7];

      m[0][1] = r[0] ^ d;
      m[1][1] = r[1] ^ d;
      m[2][1] = r[2] ^ d;
      m[3][1] = r[3] ^ d;
      m[4][1] = r[4] ^ d;
      m[5][1] = r[5] ^ d;
      m[6][1] = r[6] ^ d;
      m[7][1] = r[7] ^ d;

      auto iter = (block *)m;
      mAesFixedKey.hashBlocks<8>(iter, iter);

      iter += 8;
      mAesFixedKey.hashBlocks<8>(iter, iter);

      m += 8;
      r += 8;
    }
    for (u64 i = n8; i < (u64)messages.size(); ++i) {
      messages[i][0] = (mB[i]) & mask;
      messages[i][1] = (mB[i] ^ d) & mask;

      messages[i][0] = mAesFixedKey.hashBlock(messages[i][0]);
      messages[i][1] = mAesFixedKey.hashBlock(messages[i][1]);
    }
  } else {
    throw RTE_LOC;
  }

  setTimePoint("sender.expand.ldpc.mHash");
}

void SilentOtExtSender::silentSend(block d, span<block> b, PRNG &prng,
                                   std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, d, b, &prng, &chl);
  // MC_AWAIT(silentSendInplace(d, b.size(), prng, chl));
  silentSendInplace(d, b.size(), prng, chl);

  std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
  setTimePoint("sender.expand.ldpc.copy");
  clear();
}

void SilentOtExtSender::silentSendInplace(block d, u64 n, PRNG &prng,
                                          std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, d, n, &prng, &chl, rT = MatrixView<block>{},
  //          gapVals = std::vector<block>{}, i = u64{}, j = u64{}, main =
  //          u64{});
  MatrixView<block> rT{};
  std::vector<block> gapVals{};
  u64 i = 0;
  u64 j = 0;
  u64 main = 0;

  gTimer.setTimePoint("sender.ot.enter");
  setTimePoint("sender.expand.enter");

  if (isConfigured() == false) {
    configure(n, mScaler, mNumThreads, mMalType);
  }

  if (n != mRequestNumOts)
    throw std::invalid_argument("n != mRequestNumOts " LOCATION);

  if (hasSilentBaseOts() == false) {
    // MC_AWAIT(genSilentBaseOts(prng, chl));
    genSilentBaseOts(prng, chl);
  }

  setTimePoint("sender.expand.start");
  gTimer.setTimePoint("sender.expand.start");

  mDelta = d;

  // allocate b
  mB.resize(mN2);

  // if (mMultType == MultType::QuasiCyclic)
  //{
  //    rT = MatrixView<block>(mB.data(), 128, mN2 / 128);

  //    MC_AWAIT(mGen.expand(chl, mDelta, prng, rT,
  //    PprfOutputFormat::InterleavedTransposed, mNumThreads));
  //    setTimePoint("sender.expand.pprf_transpose");
  //    gTimer.setTimePoint("sender.expand.pprf_transpose");

  //    if (mDebug)
  //        MC_AWAIT(checkRT(chl));

  //    randMulQuasiCyclic();
  //}
  // else
  {
    main = mNumPartitions * mSizePer;
    if (mGapOts.size()) {
      // derandomize the random OTs for the gap
      // to have the desired correlation.
      gapVals.resize(mGapOts.size());
      for (i = main, j = 0; i < mN2; ++i, ++j) {
        auto v = mGapOts[j][0] ^ mDelta;
        gapVals[j] = AES(mGapOts[j][1]).ecbEncBlock(ZeroBlock) ^ v;
        mB[i] = mGapOts[j][0];
        // std::cout << "jj " << j << " " <<i << " " << mGapOts[j][0] << " " <<
        // v << " " << beta[mNumPartitions + j] << std::endl;
      }

      // MC_AWAIT(chl.send(std::move(gapVals)));
      auto status = chl->asyncSend(std::move(gapVals));
      if (!status.IsOK()) {
        LOG(ERROR) << "Send gapVals failed.";
        throw std::runtime_error("Send gapVals failed.");
      }
    }

    // MC_AWAIT(mGen.expand(chl, {&mDelta, 1}, prng, mB.subspan(0, main),
    //                      PprfOutputFormat::Interleaved, true, mNumThreads));
    mGen.expand(chl, {&mDelta, 1}, prng, mB.subspan(0, main),
                PprfOutputFormat::Interleaved, true, mNumThreads);

    if (mMalType == SilentSecType::Malicious) {
      // MC_AWAIT(ferretMalCheck(chl, prng));
      ferretMalCheck(chl, prng);
    }

    setTimePoint("sender.expand.pprf_transpose");
    gTimer.setTimePoint("sender.expand.pprf_transpose");

    if (mDebug) {
      // MC_AWAIT(checkRT(chl));
      checkRT(chl);
    }

    compress();
  }

  mB.resize(mRequestNumOts);
}

void SilentOtExtSender::ferretMalCheck(std::shared_ptr<Channel> chl,
                                       PRNG &prng) {
  // MC_BEGIN(task<>, this, &chl, &prng, X = block{}, xx = block{},
  //          sum0 = ZeroBlock, sum1 = ZeroBlock, mySum = block{},
  //          deltaShare = block{}, i = u64{}, recver = NoisyVoleReceiver{},
  //          myHash = std::array<u8, 32>{}, ro = RandomOracle(32));
  block X{};
  block xx{};
  block sum0 = ZeroBlock;
  block sum1 = ZeroBlock;
  block mySum{};
  block deltaShare{};
  u64 i = 0;
  NoisyVoleReceiver recver{};
  std::array<u8, 32> myHash{};
  RandomOracle ro(32);

  // MC_AWAIT(chl.recv(X));
  {
    auto fut = chl->asyncRecv(X);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv x failed.";
      throw std::runtime_error("Recv x failed.");
    }
  }

  xx = X;
  for (i = 0; i < (u64)mB.size(); ++i) {
    block low, high;
    xx.gf128Mul(mB[i], low, high);
    sum0 = sum0 ^ low;
    sum1 = sum1 ^ high;
    // mySum = mySum ^ xx.gf128Mul(mB[i]);

    xx = xx.gf128Mul(X);
  }

  mySum = sum0.gf128Reduce(sum1);

  // MC_AWAIT(
  //     recver.receive({&mDelta, 1}, {&deltaShare, 1}, prng, mMalCheckOts,
  //     chl));
  recver.receive({&mDelta, 1}, {&deltaShare, 1}, prng, mMalCheckOts, chl);

  ro.Update(mySum ^ deltaShare);
  ro.Final(myHash);

  // MC_AWAIT(chl.send(std::move(myHash)));
  {
    auto status = chl->asyncSend(std::move(myHash));
    if (!status.IsOK()) {
      LOG(ERROR) << "Send myHash failed.";
      throw std::runtime_error("Send myHash failed.");
    }
  }
}

void SilentOtExtSender::compress() {
  switch (mMultType) {
  case MultType::slv5:
  case MultType::slv11:
    if (mTimer)
      mEncoder.setTimer(getTimer());
    mEncoder.dualEncode<block>(mB);
    setTimePoint("sender.expand.ldpc.dualEncode");

    break;
  default:
    LOG(ERROR) << "Only support multtype slv5 and slv11.";
    throw std::runtime_error("Only support multtype slv5 and slv11.");
    break;
  }
}
//
//
//    void SilentOtExtSender::randMulQuasiCyclic()
//    {
//#ifdef ENABLE_BITPOLYMUL
//
//        const u64 rows(128);
//        auto nBlocks = mN / rows;
//        auto n2Blocks = mN2 / rows;
//        MatrixView<block> rT(mB.data(), rows, n2Blocks);
//        auto n64 = i64(nBlocks * 2);
//        std::vector<FFTPoly> a(mScaler - 1);
//        Matrix<block>cModP1(128, nBlocks, AllocType::Uninitialized);
//
//        std::unique_ptr<ThreadBarrier[]> brs(new ThreadBarrier[mScaler]);
//        for (u64 i = 0; i < mScaler; ++i)
//            brs[i].reset(mNumThreads);
//
//        auto routine = [&](u64 index)
//        {
//            u64 j = 0;
//            FFTPoly bPoly;
//            FFTPoly cPoly;
//
//            Matrix<block>tt(1, 2 * nBlocks, AllocType::Uninitialized);
//            auto temp128 = tt[0];
//
//            FFTPoly::DecodeCache cache;
//            for (u64 s = index + 1; s < mScaler; s += mNumThreads)
//            {
//                auto a64 = spanCast<u64>(temp128).subspan(n64);
//                PRNG pubPrng(toBlock(s));
//                pubPrng.get(a64.data(), a64.size());
//                a[s - 1].encode(a64);
//            }
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.randGen");
//
//            brs[j++].decrementWait();
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.randGenWait");
//
//            auto multAddReduce = [this, nBlocks, n64, &a, &bPoly, &cPoly,
//            &temp128, &cache](span<block> b128, span<block> dest)
//            {
//                for (u64 s = 1; s < mScaler; ++s)
//                {
//                    auto& aPoly = a[s - 1];
//                    auto b64 = spanCast<u64>(b128).subspan(s * n64, n64);
//
//                    bPoly.encode(b64);
//
//                    if (s == 1)
//                    {
//                        cPoly.mult(aPoly, bPoly);
//                    }
//                    else
//                    {
//                        bPoly.multEq(aPoly);
//                        cPoly.addEq(bPoly);
//                    }
//                }
//
//                // decode c[i] and store it at t64Ptr
//                cPoly.decode(spanCast<u64>(temp128), cache, true);
//
//                for (u64 j = 0; j < nBlocks; ++j)
//                    temp128[j] = temp128[j] ^ b128[j];
//
//                // reduce s[i] mod (x^n - 1) and store it at cModP1[i]
//                modp(dest, temp128, mP);
//
//            };
//
//            for (u64 i = index; i < rows; i += mNumThreads)
//                multAddReduce(rT[i], cModP1[i]);
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.mulAddReduce");
//
//            brs[j++].decrementWait();
//
//
//            std::array<block, 128> tpBuffer;
//            auto numBlocks = (mRequestNumOts + 127) / 128;
//            auto begin = index * numBlocks / mNumThreads;
//            auto end = (index + 1) * numBlocks / mNumThreads;
//            for (u64 i = begin; i < end; ++i)
//            {
//                u64 j = i * tpBuffer.size();
//                auto min = std::min<u64>(tpBuffer.size(), mN - j);
//
//                for (u64 k = 0; k < tpBuffer.size(); ++k)
//                    tpBuffer[k] = cModP1(k, i);
//
//                transpose128(tpBuffer);
//
//                auto end = i * tpBuffer.size() + min;
//                for (u64 k = 0; j < end; ++j, ++k)
//                    mB[j] = tpBuffer[k];
//            }
//
//            if (index == 0)
//                setTimePoint("sender.expand.qc.transposeXor");
//        };
//
//        std::vector<std::thread> thrds(mNumThreads - 1);
//        for (u64 i = 0; i < thrds.size(); ++i)
//            thrds[i] = std::thread(routine, i);
//
//        routine(thrds.size());
//
//        for (u64 i = 0; i < thrds.size(); ++i)
//            thrds[i].join();
//
//
//#else
//    std::cout << "bit poly mul is not enabled. Please recompile with
//    ENABLE_BITPOLYMUL defined. " LOCATION << std::endl; throw RTE_LOC;
//#endif
//
//    }
} // namespace primihub::crypto
