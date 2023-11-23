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
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>

#include "network/channel_interface.h"

#ifdef GetMessage
#undef GetMessage
#endif

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;

// The hard coded number of base OT that is expected by the OT Extension
// implementations. This can be changed if the code is adequately adapted.
const u64 gOtExtBaseOtCount(128);

class OtReceiver {
public:
  OtReceiver() = default;
  virtual ~OtReceiver() = default;

  // Receive random strings indexed by choices. The random strings will be
  // written to messages. messages must have the same alignment as an
  // AlignedBlockPtr, i.e. 32 bytes with avx or 16 bytes without avx.
  virtual void receive(const BitVector &choices, span<block> messages,
                       PRNG &prng, std::shared_ptr<Channel> chl) = 0;

  // Receive chosen strings indexed by choices. The chosen strings will be
  // written to messages. messages must have the same alignment as an
  // AlignedBlockPtr, i.e. 32 bytes with avx or 16 bytes without avx.
  void receiveChosen(const BitVector &choices, span<block> recvMessages,
                     PRNG &prng, std::shared_ptr<Channel> chl);

  void receiveCorrelated(const BitVector &choices, span<block> recvMessages,
                         PRNG &prng, std::shared_ptr<Channel> chl);
};

class OtSender {
public:
  OtSender() {}
  virtual ~OtSender() = default;

  // send random strings. The random strings will be written to
  // messages.
  virtual void send(span<std::array<block, 2>> messages, PRNG &prng,
                    std::shared_ptr<Channel> chl) = 0;

  // send chosen strings. Thosen strings are read from messages.
  void sendChosen(span<std::array<block, 2>> messages, PRNG &prng,
                  std::shared_ptr<Channel> chl);

  // No extra alignment is required.
  template <typename CorrelationFunc>
  void sendCorrelated(span<block> messages, const CorrelationFunc &corFunc,
                      PRNG &prng, std::shared_ptr<Channel> chl) {
    // MC_BEGIN(task<>, this, messages, &corFunc, &prng, &chl,
    //          temp = AlignedUnVector<std::array<block, 2>>(messages.size()),
    //          temp2 = AlignedUnVector<block>(messages.size()));
    AlignedUnVector<std::array<block, 2>> temp(messages.size());
    AlignedUnVector<std::array<block, 2>> temp2(messages.size());

    // MC_AWAIT(send(temp, prng, chl));
    send(temp, prng, chl);

    for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i) {
      messages[i] = temp[i][0];
      temp2[i] = temp[i][1] ^ corFunc(temp[i][0], i);
    }

    // MC_AWAIT(chl.send(std::move(temp2)));
    auto status = chl->asyncSend(std::move(temp2));
    if (status.IsOK()) {
      LOG(ERROR) << "Send temp2 failed.";
      throw std::runtime_error("Send temp2 failed.");
    }
  }
};

}; // namespace primihub::crypto
