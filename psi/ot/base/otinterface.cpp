#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Network/Channel.h>
#include <vector>

#include "psi/ot/base/otinterface.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;
void OtReceiver::receiveChosen(const BitVector &choices,
                               span<block> recvMessages, PRNG &prng,
                               std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, &, recvMessages,
  //          temp = std::vector<std::array<block, 2>>(recvMessages.size()));
  std::vector<std::array<block, 2>> temp;
  temp.resize(recvMessages.size());

  receive(choices, recvMessages, prng, chl);

  // MC_AWAIT(chl.recv(temp));
  auto fut = chl->asyncRecv(temp);
  auto status = fut.get();
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv content into temp failed.";
    throw std::runtime_error("Recv content into temp failed.");
  }

  {

    auto iter = choices.begin();
    for (u64 i = 0; i < temp.size(); ++i) {
      recvMessages[i] = recvMessages[i] ^ temp[i][*iter];
      ++iter;
    }
  }
}

void OtReceiver::receiveCorrelated(const BitVector &choices,
                                   span<block> recvMessages, PRNG &prng,
                                   std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, &choices, recvMessages, &prng, &chl,
  //          temp = std::vector<block>(recvMessages.size()));
  std::vector<block> temp;
  temp.resize(recvMessages.size());

  receive(choices, recvMessages, prng, chl);
  // MC_AWAIT(chl.recv(temp));
  auto fut = chl->asyncRecv(temp);
  auto status = fut.get();
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv content into temp failed.";
    throw std::runtime_error("Recv content into temp failed.");
  }

  {

    auto iter = choices.begin();
    for (u64 i = 0; i < temp.size(); ++i) {
      recvMessages[i] = recvMessages[i] ^ (zeroAndAllOne[*iter] & temp[i]);
      ++iter;
    }
  }
}

void OtSender::sendChosen(span<std::array<block, 2>> messages, PRNG &prng,
                          std::shared_ptr<Channel> chl) {
  // MC_BEGIN(task<>, this, messages, &prng, &chl,
  //          temp = std::vector<std::array<block, 2>>(messages.size()));
  std::vector<std::array<block, 2>> temp;
  temp.resize(messages.size());

  // MC_AWAIT(send(temp, prng, chl));
  send(temp, prng, chl);

  for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i) {
    temp[i][0] = temp[i][0] ^ messages[i][0];
    temp[i][1] = temp[i][1] ^ messages[i][1];
  }

  // MC_AWAIT(chl.send(std::move(temp)));
  auto status = chl->asyncSend(std::move(temp));
  if (!status.IsOK()) {
    LOG(ERROR) << "Send content in temp failed.";
    throw std::runtime_error("Send content in temp failed.");
  }
}
} // namespace primihub::crypto
