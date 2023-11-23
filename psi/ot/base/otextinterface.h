#pragma once
// © 2016 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <array>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>

#include "psi/ot/base/otinterface.h"
#include "network/channel_interface.h"

#ifdef GetMessage
#undef GetMessage
#endif

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;
class OtExtSender;
class OtExtReceiver : public OtReceiver {
public:
  OtExtReceiver() {}

  // sets the base OTs that are then used to extend
  virtual void setBaseOts(span<std::array<block, 2>> baseSendOts) = 0;

  // the number of base OTs that should be set.
  virtual u64 baseOtCount() const { return gOtExtBaseOtCount; }

  // returns true if the base OTs are currently set.
  virtual bool hasBaseOts() const = 0;

  // Returns an indpendent copy of this extender.
  virtual std::unique_ptr<OtExtReceiver> split() = 0;

  // use the default base OT class to generate the
  // base OTs that are required.
  virtual void genBaseOts(PRNG &prng, std::shared_ptr<Channel> chl);
  virtual void genBaseOts(OtSender &sender, PRNG &prng,
                          std::shared_ptr<Channel> chl);
};

class OtExtSender : public OtSender {
public:
  OtExtSender() {}

  // the number of base OTs that should be set.
  virtual u64 baseOtCount() const { return gOtExtBaseOtCount; }

  // returns true if the base OTs are currently set.
  virtual bool hasBaseOts() const = 0;

  // sets the base OTs that are then used to extend
  virtual void setBaseOts(span<block> baseRecvOts,
                          const BitVector &choices) = 0;

  // Returns an indpendent copy of this extender.
  virtual std::unique_ptr<OtExtSender> split() = 0;

  // use the default base OT class to generate the
  // base OTs that are required.
  virtual void genBaseOts(PRNG &prng, std::shared_ptr<Channel> chl);
  virtual void genBaseOts(OtReceiver &recver, PRNG &prng,
                          std::shared_ptr<Channel> chl);
};

} // namespace primihub::crypto
