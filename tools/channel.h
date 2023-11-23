#ifndef __TOOLS_CHANNEL_H_
#define __TOOLS_CHANNEL_H_

#include <future>
#include <glog/logging.h>

#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/Matrix.h>

#include "tools/status.h"

using osuCrypto::AlignedUnVector;
using osuCrypto::block;
using osuCrypto::Matrix;
using osuCrypto::span;

using primihub::crypto::Status;

namespace primihub::crypto::network {
template <typename Container>
using is_container =
    std::is_same<typename std::enable_if<
                     std::is_convertible<
                         typename Container::pointer,
                         decltype(std::declval<Container>().data())>::value &&
                     std::is_convertible<
                         typename Container::size_type,
                         decltype(std::declval<Container>().size())>::value &&
                     std::is_pod<typename Container::value_type>::value &&
                     std::is_pod<Container>::value == false>::type,
                 void>;

class CryptoChannel {
public:
  virtual ~CryptoChannel() {}
  virtual Status initChannel(void) { return Status::NotImplementError(); }
  virtual std::string getTag(void) { return std::string(""); }
  virtual std::future<Status> asyncSend(void *ptr, size_t send_size) = 0;
  virtual std::future<Status> asyncRecv(void *ptr, size_t recv_size) = 0;
  virtual Status recvResize(std::string &container) = 0;
  virtual std::shared_ptr<CryptoChannel> fork(void) = 0;

  template <typename Container>
  typename std::enable_if<is_container<Container>::value,
                          typename std::future<Status>>::type
  asyncSend(const Container &data);

  template <typename Container>
  typename std::enable_if<is_container<Container>::value,
                          typename std::future<Status>>::type
  asyncSend(const Container &&data);

  template <typename Container>
  typename std::enable_if<is_container<Container>::value,
                          typename std::future<Status>>::type
  asyncRecv(Container &data);

  template <typename Container>
  typename std::enable_if<is_container<Container>::value,
                          typename std::future<Status>>::type
  asyncRecv(Container &&data);

  template <typename T>
  typename std::enable_if<std::is_pod<T>::value,
                          typename std::future<Status>>::type
  asyncSend(const T &t);

  template <typename T>
  typename std::enable_if<std::is_pod<T>::value,
                          typename std::future<Status>>::type
  asyncSend(const T &&t);

  template <typename T>
  typename std::enable_if<std::is_pod<T>::value,
                          typename std::future<Status>>::type
  asyncRecv(T &t);

  template <typename T>
  typename std::enable_if<std::is_pod<T>::value,
                          typename std::future<Status>>::type
  asyncRecv(T &&t);

  Status recvResize(std::vector<block> &container);
};

template <typename Container>
typename std::enable_if<is_container<Container>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncSend(const Container &container) {
  return asyncSend(std::move(container));
}

template <typename Container>
typename std::enable_if<is_container<Container>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncSend(const Container &&container) {
  size_t send_size = sizeof(typename Container::value_type) * container.size();
  void *send_ptr = reinterpret_cast<void *>(
      const_cast<typename Container::value_type *>(container.data()));
  return asyncSend(send_ptr, send_size);
}

template <typename T>
typename std::enable_if<std::is_pod<T>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncSend(const T &t) {
  return asyncSend(std::move(t));
}

template <typename T>
typename std::enable_if<std::is_pod<T>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncSend(const T &&t) {
  size_t send_size = sizeof(T);
  void *send_ptr = reinterpret_cast<void *>(const_cast<T *>(&t));
  return asyncSend(send_ptr, send_size);
}

template <typename Container>
typename std::enable_if<is_container<Container>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncRecv(Container &container) {
  return asyncRecv(std::move(container));
}

template <typename Container>
typename std::enable_if<is_container<Container>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncRecv(Container &&container) {
  size_t recv_size = sizeof(typename Container::value_type) * container.size();
  void *recv_ptr = reinterpret_cast<void *>(container.data());

  return asyncRecv(recv_ptr, recv_size);
}

template <typename T>
typename std::enable_if<std::is_pod<T>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncRecv(T &t) {
  return asyncRecv(std::move(t));
}

template <typename T>
typename std::enable_if<std::is_pod<T>::value,
                        typename std::future<Status>>::type
CryptoChannel::asyncRecv(T &&t) {
  size_t recv_size = sizeof(T);
  void *recv_ptr = reinterpret_cast<void *>(&t);

  return asyncRecv(recv_ptr, recv_size);
}
}; // namespace primihub::crypto::network

#endif
