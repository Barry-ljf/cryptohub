#include "tools/channel.h"

namespace primihub::crypto::network {
Status CryptoChannel::recvResize(std::vector<block> &container) {
  std::string tmp;
  auto status = recvResize(tmp);
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv message into temporary container failed.";
    return status;
  }

  size_t num_block = tmp.size() / sizeof(block);
  container.resize(num_block);

  uint8_t *dest = reinterpret_cast<uint8_t *>(container.data());
  uint8_t *src = reinterpret_cast<uint8_t *>(tmp.data());

  memcpy(dest, src, tmp.size());

  return Status::OK();
}

}; // namespace primihub::crypto::network
