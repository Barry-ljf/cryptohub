#ifndef __TOOLS_SOCKET_H_
#define __TOOLS_SOCKET_H_

#include <iostream>
#include <string>

#include "tools/channel.h"
#include "tools/status.h"

using primihub::crypto::Status;

namespace primihub::crypto::network {
class NamedSocket {
public:
  NamedSocket(const std::string &host, const uint16_t port,
              const std::string &tag);
  virtual Status startServerLoop(void);
  virtual Status startRecvLoop(void);
  virtual Status initSocket(void);
  virtual Status sendMessageWithTag(void *ptr, size_t size);
  virtual Status sendMessageWithTag(void *ptr, size_t size,
                                    const std::string &tag);
  virtual Status getMessageWithTag(const uint16_t buff_index, void *ptr,
                                   size_t size, const std::string &tag,
                                   uint16_t timeout = 300);
  virtual Status getMessageWithTag(const uint16_t buff_index, void *ptr,
                                   size_t size, uint16_t timeout = 300);
  virtual Status getMessageWithTag(const uint16_t buff_index,
                                   std::string &container,
                                   const std::string &tag,
                                   uint16_t timeout = 300);
  virtual Status getMessageWithTag(const uint16_t buff_index,
                                   std::string &container,
                                   uint16_t timeout = 300);

  virtual Status allocBufferForFill(const std::string &tag,
                                    uint16_t &buff_index);
  virtual Status allocBufferForRead(const std::string &tag,
                                    uint16_t &buff_index);
  virtual Status freeBuffer(const std::string &tag, const uint16_t buff_index);

protected:
  std::string tag_;
  std::string host_;
  uint16_t port_;
};

class ClientChannel : public CryptoChannel {
public:
  ClientChannel(const std::string &host, const uint16_t port,
                const std::string &tag);
  ~ClientChannel();
  Status initChannel(void);
  std::future<Status> asyncSend(void *ptr, size_t send_size);
  std::future<Status> asyncRecv(void *ptr, size_t recv_size);
  Status recvResize(std::string &container);
  std::shared_ptr<CryptoChannel> fork(void);
  std::string getTag(void);

private:
  std::string deriveNewTag(void);

  std::shared_ptr<NamedSocket> sock_;
  std::vector<std::shared_ptr<ClientChannel>> forked_channel_;

  std::string tag_;
  std::string host_;
  uint16_t port_;
  uint16_t num_fork_;
};

class ServerChannel : public CryptoChannel {
public:
  ServerChannel(const std::string &host, const uint16_t port,
                const std::string &tag);
  ~ServerChannel();
  Status initChannel(void);
  std::future<Status> asyncSend(void *ptr, size_t send_size);
  std::future<Status> asyncRecv(void *ptr, size_t recv_size);
  Status recvResize(std::string &container);
  std::shared_ptr<CryptoChannel> fork(void);
  std::string getTag(void);

private:
  std::string deriveNewTag(void);

  std::shared_ptr<NamedSocket> sock_;
  std::vector<std::shared_ptr<ServerChannel>> forked_channel_;

  std::string tag_;
  std::string host_;
  uint16_t port_;
  uint16_t num_fork_;
};

} // namespace primihub::crypto::network

#endif
