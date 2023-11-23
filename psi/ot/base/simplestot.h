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

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

#include "psi/ot/base/otinterface.h"
#include "network/channel_interface.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel; 
class SimplestOT : public OtReceiver, public OtSender {
public:
  // set this to false if your use of the base OTs can tolerate
  // the receiver being able to choose the message that they receive.
  // If unsure leave as true as the strings will be uniform (safest but slower).
  bool mUniformOTs = true;

  void receive(const BitVector &choices, span<block> messages, PRNG &prng,
               std::shared_ptr<Channel> chl, u64 numThreads) {
    return receive(choices, messages, prng, chl);
  }

  void send(span<std::array<block, 2>> messages, PRNG &prng,
            std::shared_ptr<Channel> chl, u64 numThreads) {
    return send(messages, prng, chl);
  }

  void receive(const BitVector &choices, span<block> messages, PRNG &prng,
               std::shared_ptr<Channel> chl) override;

  void send(span<std::array<block, 2>> messages, PRNG &prng,
            std::shared_ptr<Channel> chl) override;
};
} // namespace primihub::crypto
