#ifndef RSOPRF_H_
#define RSOPRF_H_

#include <glog/logging.h>

#include "psi/okvs/defines.h"
#include "psi/okvs/paxos.h"
#include "psi/okvs/pxutil.h"

// #include "volePSI/Defines.h"
// #include "volePSI/config.h"
#include "psi/ot/vole/silent/silentvolereceiver.h"
#include "psi/ot/vole/silent/silentvolesender.h"

// #include "libOTe/Vole/Silent/SilentVoleSender.h"
// #include "libOTe/Vole/Silent/SilentVoleReceiver.h"

namespace primihub::crypto {

class RsOprfSender : public oc::TimerAdapter {
 public:
  crypto::SilentVoleSender mVoleSender;
  span<block> mB;
  block mD;
  crypto::okvs::Baxos mPaxos;
  bool mMalicious = false;
  block mW;
  u64 mBinSize = 1 << 14;
  u64 mSsp = 40;
  bool mDebug = false;
  using PaxosParam = crypto::okvs::PaxosParam;

  void setMultType(MultType type) { mVoleSender.mMultType = type; };

  void send(u64 n, PRNG& prng, const std::shared_ptr<Channel>& chl,
            u64 mNumThreads = 0, bool reducedRounds = false);

  block eval(block v);

  void eval(span<const block> val, span<block> output, u64 mNumThreads = 0);

  void genVole(PRNG& prng, const std::shared_ptr<Channel>& chl,
               bool reducedRounds);
};

class RsOprfReceiver : public oc::TimerAdapter {
 public:
  bool mMalicious = false;
  crypto::SilentVoleReceiver mVoleRecver;
  u64 mBinSize = 1 << 14;
  u64 mSsp = 40;
  bool mDebug = false;

  void setMultType(MultType type) { mVoleRecver.mMultType = type; };

  void receive(span<const block> values, span<block> outputs, PRNG& prng,
               const std::shared_ptr<Channel>& chl, u64 mNumThreads = 0,
               bool reducedRounds = false);

  void genVole(u64 n, PRNG& prng, const std::shared_ptr<Channel>& chl,
               bool reducedRounds);
};
}  // namespace primihub::crypto
#endif