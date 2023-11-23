#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <tuple>

#include <arpa/inet.h>
#include <assert.h>
#include <glog/logging.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket.h"

namespace primihub::crypto::network {
namespace {
ssize_t readn(int fd, void *vptr, size_t n) {
  size_t nleft;
  ssize_t nread;
  char *ptr;

  ptr = reinterpret_cast<char *>(vptr);
  nleft = n;
  while (nleft > 0) {
    if ((nread = read(fd, ptr, nleft)) < 0) {
      if (errno == EINTR) {
        nread = 0; // Call read() again.
      } else {
        LOG(ERROR) << "Run read failed, " << strerror(errno) << ".";
        return (-1);
      }
    } else if (nread == 0)
      break; // EOF

    nleft -= nread;
    ptr += nread;
  }

  return (n - nleft);
}

ssize_t writen(int fd, const void *vptr, size_t n) {
  size_t nleft;
  ssize_t nwritten;
  const char *ptr;

  ptr = reinterpret_cast<const char *>(vptr);
  nleft = n;
  while (nleft > 0) {
    if ((nwritten = write(fd, ptr, nleft)) <= 0) {
      if (nwritten < 0 && errno == EINTR) {
        nwritten = 0; // Call write() again.
      } else {
        LOG(ERROR) << "Run write failed, " << strerror(errno) << ".";
        return (-1);
      }
    }

    nleft -= nwritten;
    ptr += nwritten;
  }
  return (n);
}

class NetworkBuffer {
public:
  NetworkBuffer() {
    buf_ = nullptr;
    aux_buf_ = nullptr;
    buf_size_ = 0;
    filled_.store(false);
  }

  NetworkBuffer(NetworkBuffer &&other) {
    this->aux_buf_ = other.aux_buf_;
    this->buf_ = other.buf_;
    this->buf_size_ = other.buf_size_;
    this->filled_.store(other.filled_.load());

    other.aux_buf_ = nullptr;
    other.buf_ = nullptr;
    other.buf_size_ = 0;
    other.filled_.store(false);
  }

  ~NetworkBuffer() {}

  // Below three method is called in message recv thread.
  Status getBufferPtr(size_t recv_size, void **ptr) {
    std::lock_guard<std::mutex> lock(buf_mu_);
    *ptr = buf_;
    return Status::OK();
  }

  void putBufferPtr(__attribute__((unused)) void *ptr) {
    std::unique_lock<std::mutex> lock(cond_mu_);
    filled_.store(true);
    cond_.notify_all();
  }

  Status initBuffer(size_t recv_size) {
    std::lock_guard<std::mutex> lock(buf_mu_);
    if (nullptr == buf_) {
      buf_ = new char[recv_size];
      buf_size_ = recv_size;
      VLOG(5) << "Nobody provide buffer now, create it directly.";
      return Status::OK();
    } else {
      if (recv_size != buf_size_) {
        LOG(ERROR)
            << "Size mismatch between message and message buffer, message size "
            << recv_size << ", buffer size " << buf_size_ << ".";
        return Status::MismatchError();
      }
    }

    return Status::OK();
  }

  // Below two methods are called in algorithm thread.
  Status provideBuffer(void *ptr, size_t size) {
    std::lock_guard<std::mutex> lock(buf_mu_);
    if (nullptr == buf_) {
      buf_ = reinterpret_cast<char *>(ptr);
      buf_size_ = size;
      VLOG(5) << "The buffer will be used for socket operation.";
    } else {
      aux_buf_ = reinterpret_cast<char *>(ptr);
      if (buf_size_ != size) {
        LOG(ERROR) << "Length of recv message is " << buf_size_
                   << ", but the size of recv buffer is " << size
                   << ", size mismatch.";
        return Status::MismatchError();
      }

      VLOG(5) << "Create a auxiliary buffer, copy content to it after recv.";
    }

    return Status::OK();
  }

  Status consumeBuffer(void **msg_ptr, size_t &msg_size, uint32_t timeout) {
    std::unique_lock<std::mutex> lock(cond_mu_);

    cond_.wait_for(lock, std::chrono::seconds(timeout),
                   [this]() { return filled_.load(); });
    if (filled_.load() == false) {
      return Status::TimeoutError();
    } else {
      if (nullptr == aux_buf_) {
        *msg_ptr = buf_;
        msg_size = buf_size_;
        reset(false);
      } else {
        memcpy(aux_buf_, buf_, buf_size_);
        *msg_ptr = aux_buf_;
        msg_size = buf_size_;
        reset(true);
      }

      return Status::OK();
    }
  }

private:
  void reset(bool heap_alloc) {
    if (heap_alloc)
      delete buf_;
    buf_ = nullptr;
    aux_buf_ = nullptr;
    buf_size_ = 0;
  }

  char *buf_;
  char *aux_buf_;
  size_t buf_size_;
  std::mutex buf_mu_;

  std::atomic<bool> filled_;

  std::mutex cond_mu_;
  std::condition_variable cond_;
};

class MultipleNetworkBuffer {
public:
  MultipleNetworkBuffer() {
    const uint16_t total = 1024;
    for (uint16_t i = 0; i < total; i++) {
      provide_indexes_.push(i);
      consume_indexes_.push(i);
    }

    buffers_.resize(total);
  }

  MultipleNetworkBuffer(MultipleNetworkBuffer &&other) {
    this->buffers_ = std::move(other.buffers_);
    this->consume_indexes_ = std::move(other.consume_indexes_);
    this->provide_indexes_ = std::move(other.provide_indexes_);
  }

  Status getBufferForFill(uint16_t &index, NetworkBuffer **ptr) {
    std::lock_guard<std::mutex> lock(provide_mu_);
    if (provide_indexes_.size() == 0) {
      LOG(ERROR) << "No free slot error.";
      return Status::UnavailableError();
    }

    index = provide_indexes_.front();
    *ptr = &buffers_[index];
    provide_indexes_.pop();
    return Status::OK();
  };

  Status getBufferForRead(uint16_t &index, NetworkBuffer **ptr) {
    std::lock_guard<std::mutex> lock(consume_mu_);
    if (consume_indexes_.size() == 0) {
      LOG(ERROR) << "No free slot error.";
      return Status::UnavailableError();
    }

    index = consume_indexes_.front();
    *ptr = &buffers_[index];
    consume_indexes_.pop();
    return Status::OK();
  }

  void putBuffer(const uint16_t index) {
    // Using std::deque might be more better than std::queue in this scenario.
    // This is due to the fact that a buffer is appended to the end of the queue
    // when it's freed. This buffer could potentially be reused after receiving
    // data for up to 1023 times. It's more beneficial for the buffer to be
    // reused as promptly as feasible.
    {
      std::lock_guard<std::mutex> lock(provide_mu_);
      provide_indexes_.push(index);
    }

    {
      std::lock_guard<std::mutex> lock(consume_mu_);
      consume_indexes_.push(index);
    }
  }

  Status getBufferWithIndex(const uint16_t index, NetworkBuffer **buff) {
    if (index > 1024) {
      LOG(ERROR) << "Index out of range error.";
      return Status::InvalidError();
    }

    *buff = &buffers_[index];
    return Status::OK();
  }

private:
  std::mutex provide_mu_;
  std::mutex consume_mu_;
  std::vector<NetworkBuffer> buffers_;
  std::queue<uint16_t> provide_indexes_;
  std::queue<uint16_t> consume_indexes_;
};

class RecvBufferManager {
public:
  RecvBufferManager() {}

  Status getOrCreateBufferForFill(const std::string &key, uint16_t &index,
                                  bool fill) {
    std::lock_guard<std::mutex> lock(tag_buff_mu_);
    NetworkBuffer *dummy = nullptr;
    auto iter = tag_buff_map_.find(key);
    if (iter == tag_buff_map_.end()) {
      auto ret =
          tag_buff_map_.insert(std::make_pair(key, MultipleNetworkBuffer()));
      auto &buffers = ret.first->second;
      if (fill)
        return buffers.getBufferForFill(index, &dummy);
      else
        return buffers.getBufferForRead(index, &dummy);
    }

    auto &buffers = iter->second;
    if (fill)
      return buffers.getBufferForFill(index, &dummy);
    else
      return buffers.getBufferForRead(index, &dummy);
  }

  Status getBufferWithIndex(const std::string &key, const uint16_t index,
                            NetworkBuffer **buff) {
    std::lock_guard<std::mutex> lock(tag_buff_mu_);
    auto iter = tag_buff_map_.find(key);
    if (iter == tag_buff_map_.end()) {
      LOG(ERROR) << "Can't find recv buffers with key " << key << ".";
      return Status::NotFoundError();
    }

    auto &buffers = iter->second;
    buffers.getBufferWithIndex(index, buff);
    return Status::OK();
  }

  Status putBuffer(const std::string &key, const uint16_t index) {
    std::lock_guard<std::mutex> lock(tag_buff_mu_);
    auto iter = tag_buff_map_.find(key);
    if (iter == tag_buff_map_.end()) {
      LOG(ERROR) << "Can't find recv buffers with key " << key << ".";
      return Status::NotFoundError();
    }

    auto &buffers = iter->second;
    buffers.putBuffer(index);
  }

  Status destroyRecvBuffer(const std::string &key) {
    std::lock_guard<std::mutex> lock(tag_buff_mu_);
    auto iter = tag_buff_map_.find(key);
    if (iter == tag_buff_map_.end()) {
      LOG(WARNING) << "Can't find recv buffer with key " << key << ".";
      return Status::NotFoundError();
    }

    tag_buff_map_.erase(iter);

    VLOG(5) << "Destroy recv buffer with tag " << key << ".";
    return Status::OK();
  }

  size_t size(void) { return tag_buff_map_.size(); }

private:
  std::mutex tag_buff_mu_;
  std::map<std::string, MultipleNetworkBuffer> tag_buff_map_;
};

class ServerSocket : public NamedSocket {
public:
  ServerSocket(const std::string &host, const uint16_t port,
               const std::string &tag)
      : NamedSocket(host, port, tag) {
    valid_flag_.store(false);
    loop_started_flag_.store(false);
  }

  ~ServerSocket() {
    // Stop epoll thread.
    stopServerLoop();

    // Close all client socket.
    std::vector<std::string> all_tags;
    {
      std::lock_guard<std::mutex> lock(fd_tag_mu_);
      for (auto &item : fd_tag_map_) {
        std::lock_guard<std::mutex> lock(item.second.mu_);
        close(item.second.clientfd_);
        all_tags.emplace_back(item.second.tag_);
      }
    }

    for (const auto &tag : all_tags)
      manager_.destroyRecvBuffer(tag);

    fd_tag_map_.clear();
    loop_started_flag_.store(false);
  }

  Status allocBufferForFill(const std::string &tag, uint16_t &buff_index) {
    return manager_.getOrCreateBufferForFill(tag, buff_index, true);
  }

  Status allocBufferForRead(const std::string &tag, uint16_t &buff_index) {
    NetworkBuffer *buff = nullptr;
    return manager_.getOrCreateBufferForFill(tag, buff_index, false);
  }

  Status freeBuffer(const std::string &tag, const uint16_t buff_index) {
    return manager_.putBuffer(tag, buff_index);
  }

  Status getMessageWithTag(const uint16_t index, std::string &container,
                           const std::string &tag, uint16_t timeout) {
    if (!valid_flag_.load()) {
      LOG(ERROR) << "Invalid server socket, forbid recv operation.";
      return Status::InvalidError();
    }

    NetworkBuffer *recv_buff = nullptr;
    auto status = manager_.getBufferWithIndex(tag, index, &recv_buff);
    if (!status.IsOK()) {
      LOG(ERROR) << "Failed to get buffer with tag " << tag << ", index "
                 << index << ".";
      return Status::InvalidError();
    }

    // Default timeout is 5 minutes.
    void *ret_ptr = nullptr;
    size_t ret_size = 0;
    status = recv_buff->consumeBuffer(&ret_ptr, ret_size, timeout);
    if (!status.IsOK()) {
      LOG(WARNING) << "Get message with tag " << tag << " and index " << index
                   << " failed, timeout.";
      manager_.putBuffer(tag, index);
      return Status::TimeoutError();
    }

    container.resize(ret_size);
    memcpy(reinterpret_cast<uint8_t *>(container.data()),
           reinterpret_cast<uint8_t *>(ret_ptr), ret_size);

    manager_.putBuffer(tag, index);
    ret_ptr = nullptr;
    ret_size = 0;

    VLOG(5) << "Free buffer, index " << index << ", tag " << tag << ".";
    VLOG(5) << "Get message with tag " << tag << " finish, message size "
            << container.size() << ".";
    return Status::OK();
  }

  Status getMessageWithTag(const uint16_t index, void *ptr, size_t recv_size,
                           const std::string &tag, uint16_t timeout) {
    if (!valid_flag_.load()) {
      LOG(ERROR) << "Invalid server socket, forbid recv operation.";
      return Status::InvalidError();
    }

    NetworkBuffer *recv_buff = nullptr;
    auto status = manager_.getBufferWithIndex(tag, index, &recv_buff);
    if (!status.IsOK()) {
      LOG(ERROR) << "Failed to get buffer with tag " << tag << ", index "
                 << index << ".";
      return Status::InvalidError();
    }

    status = recv_buff->provideBuffer(ptr, recv_size);
    if (!status.IsOK()) {
      LOG(ERROR) << "Provide buffer for read failed, message tag " << tag
                 << ".";
      return status;
    }

    // Default timeout is 5 minutes.
    void *ret_ptr = nullptr;
    size_t ret_size = 0;
    status = recv_buff->consumeBuffer(&ret_ptr, ret_size, timeout);
    if (!status.IsOK()) {
      LOG(WARNING) << "Get message with tag " << tag << " and index " << index
                   << " failed, timeout.";
      manager_.putBuffer(tag, index);
      return Status::TimeoutError();
    }

    assert(ret_ptr == ptr);
    assert(ret_size == recv_size);

    manager_.putBuffer(tag, index);

    VLOG(5) << "Free buffer, index " << index << ", tag " << tag << ".";
    VLOG(5) << "Get message with tag " << tag << " finish, message size "
            << recv_size << ".";
    return Status::OK();
  }

  Status sendMessageWithTag(void *ptr, size_t send_size,
                            const std::string &tag) {
    if (!valid_flag_.load()) {
      LOG(ERROR) << "Invalid server socket, forbid any send operation.";
      return Status::InvalidError();
    }

    std::map<std::string, InnerClientSocket>::iterator iter;
    {
      std::lock_guard<std::mutex> lock(fd_tag_mu_);
      iter = fd_tag_map_.find(tag);
      if (iter == fd_tag_map_.end()) {
        LOG(ERROR) << "Can't find client socket with tag " << tag << ".";
        return Status::NotFoundError();
      }
    }

    auto &client_socket = iter->second;
    std::lock_guard<std::mutex> lock(client_socket.mu_);

    uint32_t u32_size = send_size;
    ssize_t send_bytes =
        writen(client_socket.clientfd_, &u32_size, sizeof(uint32_t));
    if (send_bytes != sizeof(uint32_t)) {
      LOG(ERROR) << "Send message size failed, tag " << tag << ".";
      close(client_socket.clientfd_);
      return Status::NetworkError();
    }

    send_bytes = writen(client_socket.clientfd_, ptr, send_size);
    if (send_bytes != static_cast<ssize_t>(send_size)) {
      LOG(ERROR) << "Send message failed, message size " << send_size
                 << ", tag " << tag << ".";
      // Let epoll thread find this bad socket.
      close(client_socket.clientfd_);
      return Status::NetworkError();
    }

    return Status::OK();
  }

  Status startServerLoop(void) {
    if (!loop_started_flag_.load()) {
      auto status = initServerSocket();
      if (!status.IsOK())
        return status;

      valid_flag_.store(true);

      VLOG(3) << "Server socket is ready.";

      recv_loop_ = std::thread(&ServerSocket::serverLoop, this);
      loop_started_flag_.store(true);
    }

    return Status::OK();
  }

  bool validSocket(void) { return valid_flag_.load(); }

private:
  struct InnerClientSocket {
    InnerClientSocket() {}
    InnerClientSocket &operator=(const InnerClientSocket &other) {
      if (this == &other)
        return *this;

      this->clientfd_ = other.clientfd_;
      this->tag_ = other.tag_;
      return *this;
    }

    int clientfd_{0};
    std::mutex mu_;
    std::string tag_{""};
  };

  void serverLoop(void) {
    struct epoll_event event;
    event.data.fd = server_fd_;
    event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    const uint16_t max_events = 32;

    int efd = epoll_create1(0);
    if (efd == -1) {
      LOG(ERROR) << "Create epoll fd failed, " << strerror(errno) << ".";
      valid_flag_.store(false);
      return;
    }

    int ret = epoll_ctl(efd, EPOLL_CTL_ADD, server_fd_, &event);
    if (ret == -1) {
      LOG(ERROR) << "Run epoll_ctl failed, " << strerror(errno) << ".";
      valid_flag_.store(false);
      return;
    }

    std::array<struct epoll_event, max_events> all_events;
    struct epoll_event *event_ptr = all_events.data();
    bool errors = false;
    while (valid_flag_.load() == true) {
      int n = epoll_wait(efd, event_ptr, max_events, 100);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        } else {
          LOG(ERROR) << "Run epoll_wait failed, " << strerror(errno) << ".";
          valid_flag_.store(false);
          errors = true;
          break;
        }
      }

      for (int i = 0; i < n; i++) {
        if ((event_ptr[i].events & EPOLLERR) ||
            (event_ptr[i].events & EPOLLHUP) ||
            !(event_ptr[i].events & EPOLLIN)) {
          InnerClientSocket *sock_ptr =
              reinterpret_cast<InnerClientSocket *>(event_ptr[i].data.ptr);
          const std::string &tag = sock_ptr->tag_;
          int client_fd = sock_ptr->clientfd_;
          closeSocketThenClean(client_fd, efd, tag);

          // Peer close or error.
          if (event_ptr[i].events & EPOLLHUP)
            LOG(WARNING) << "Close client socket due to peer close, tag " << tag
                         << ".";
          else
            LOG(WARNING) << "Close client socket due to error, tag " << tag
                         << ".";
        } else if (event_ptr[i].data.fd == server_fd_) {
          // New tcp connection comes.
          struct sockaddr in_addr;
          socklen_t in_len = sizeof(in_addr);

          int client_fd = accept(server_fd_, &in_addr, &in_len);
          if (client_fd == -1) {
            LOG(ERROR) << "Run accept failed, " << strerror(errno) << ".";
            continue;
          } else {
            std::string tag = "";
            uint32_t tag_len = 0;

            ssize_t recv_size =
                readn(client_fd, reinterpret_cast<void *>(&tag_len),
                      sizeof(uint32_t));
            if (recv_size != sizeof(uint32_t)) {
              LOG(ERROR) << "Recv length of tag failed, close connection.";
              close(client_fd);
              continue;
            }

            tag.resize(tag_len);
            recv_size =
                readn(client_fd, reinterpret_cast<void *>(tag.data()), tag_len);
            if (recv_size != tag_len) {
              LOG(ERROR) << "Recv tag string failed, expect " << tag_len
                         << " bytes but gives " << recv_size << " bytes.";
              LOG(ERROR) << "Close connection due to recv tag error.";
              close(client_fd);
              continue;
            }

            bool dup_tag = false;
            {
              std::lock_guard<std::mutex> lock(fd_tag_mu_);
              auto iter = fd_tag_map_.find(tag);
              if (iter != fd_tag_map_.end()) {
                LOG(ERROR) << "Another tcp connection has the same tag " << tag
                           << ".";
                LOG(ERROR) << "Close connection due to duplicate tag.";
                close(client_fd);
                dup_tag = true;
              } else {
                InnerClientSocket sock;
                sock.tag_ = tag;
                sock.clientfd_ = client_fd;
                fd_tag_map_[tag] = sock;
              }
            }

            if (dup_tag)
              continue;

            struct epoll_event new_event;
            auto iter = fd_tag_map_.find(tag);
            new_event.data.ptr = &(iter->second);
            new_event.events = EPOLLIN | EPOLLERR | EPOLLHUP;

            ret = epoll_ctl(efd, EPOLL_CTL_ADD, client_fd, &new_event);
            if (ret == -1) {
              errors = true;
              close(client_fd);
              manager_.destroyRecvBuffer(tag);
              LOG(ERROR) << "Run epoll_ctl failed, " << strerror(errno) << ".";
              continue;
            }

            VLOG(3) << "Accept new tcp connection, tag " << tag << ".";
          }
        } else {
          InnerClientSocket *sock_ptr =
              reinterpret_cast<InnerClientSocket *>(event_ptr[i].data.ptr);
          int client_fd = sock_ptr->clientfd_;
          std::string &tag = sock_ptr->tag_;

          uint32_t msg_size = 0;
          ssize_t recv_size = readn(client_fd, &msg_size, sizeof(uint32_t));
          if (recv_size != sizeof(uint32_t)) {
            if (recv_size == 0) {
              closeSocketThenClean(client_fd, efd, tag);
              continue;
            }

            LOG(ERROR) << "Recv message size failed, close client socket, tag "
                       << tag << ".";
            closeSocketThenClean(client_fd, efd, tag);
            continue;
          }

          uint16_t index;
          NetworkBuffer *recv_buff = nullptr;
          auto status = allocBufferForFill(tag, index);
          if (!status.IsOK()) {
            closeSocketThenClean(client_fd, efd, tag);
            LOG(ERROR) << "Can't get recv buffer with tag " << tag << ".";
            continue;
          }

          VLOG(5) << "Allocate buffer for fill, message size " << msg_size
                  << ", index " << index << ", tag " << tag << ".";

          manager_.getBufferWithIndex(tag, index, &recv_buff);

          void *ptr = nullptr;
          status = recv_buff->initBuffer(msg_size);
          if (!status.IsOK()) {
            LOG(ERROR) << "Run initBuffer failed, message tag " << tag << ".";
            closeSocketThenClean(client_fd, efd, tag);
            continue;
          }

          recv_buff->getBufferPtr(msg_size, &ptr);

          recv_size = readn(client_fd, ptr, msg_size);
          if (recv_size != static_cast<ssize_t>(msg_size)) {
            if (recv_size == 0) {
              closeSocketThenClean(client_fd, efd, tag);
              continue;
            }

            closeSocketThenClean(client_fd, efd, tag);
            LOG(ERROR) << "Can't read " << msg_size
                       << " bytes message failed, tag " << tag << ".";
            continue;
          }

          VLOG(5) << "Recv " << msg_size << " bytes message finish, tag " << tag
                  << ".";
          recv_buff->putBufferPtr(ptr);
        }

        if (errors)
          break;
      }
    }

    // Remove server socket from epoll.
    bzero(&event, sizeof(event));
    epoll_ctl(efd, EPOLL_CTL_DEL, server_fd_, &event);

    // Close server socket.
    close(server_fd_);
    close(efd);

    if (errors)
      LOG(ERROR) << "Stop server recv loop due to error.";
    else
      VLOG(3) << "Server recv loop stops due to stop signal.";
  }

  void closeSocketThenClean(int sock_fd, int efd, const std::string &tag) {
    // This method runs in epoll thread, perform the following operation:
    // 1.remove from epoll;
    // 2.clean recv buffer;
    // 3.remove from fd_tag_map;
    // 4.close socket.
    struct epoll_event event;
    bzero(&event, sizeof(event));
    epoll_ctl(efd, EPOLL_CTL_DEL, sock_fd, &event);

    manager_.destroyRecvBuffer(tag);

    {
      std::lock_guard<std::mutex> lock(fd_tag_mu_);
      auto iter = fd_tag_map_.find(tag);
      fd_tag_map_.erase(iter);
    }

    close(sock_fd);
  }

  Status initServerSocket(void) {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
      LOG(ERROR) << "Create server socket failed, " << strerror(errno) << ".";
      valid_flag_.store(false);
      return Status::SyscallError();
    }

    int flag = 1;
    int len = sizeof(int);
    int ret = setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &flag, len);
    if (ret) {
      LOG(ERROR) << "Run setsockopt failed, " << strerror(errno) << ".";
      valid_flag_.store(false);
      return Status::SyscallError();
    }

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = inet_addr(host_.c_str());
    bind_addr.sin_port = htons(port_);

    ret = bind(server_fd_, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (ret == -1) {
      LOG(ERROR) << "Bind socket to " << host_ << ":" << port_ << " failed, "
                 << strerror(errno) << ".";
      valid_flag_.store(false);
      return Status::SyscallError();
    }

    ret = listen(server_fd_, 100);
    if (ret == -1) {
      LOG(ERROR) << "Socket listen failed, " << strerror(errno) << ".";
      valid_flag_.store(false);
      return Status::SyscallError();
    }

    return Status::OK();
  }

  void stopServerLoop(void) {
    valid_flag_.store(false);
    recv_loop_.join();
  }

  int server_fd_{0};

  std::thread recv_loop_;
  std::atomic<bool> valid_flag_;
  std::atomic<bool> loop_started_flag_;

  std::mutex fd_tag_mu_;
  std::map<std::string, InnerClientSocket> fd_tag_map_;

  RecvBufferManager manager_;
};

class ServerSocketManager {
public:
  std::shared_ptr<NamedSocket> getOrCreateServerSocket(const std::string &host,
                                                       const uint16_t port) {
    std::string key = "server_" + host + "_" + std::to_string(port);
    std::lock_guard<std::mutex> lock(mu_);

    auto iter = sock_map_.find(key);
    if (iter != sock_map_.end()) {
      auto &sock_with_ref = iter->second;
      uint16_t ref_cnt = sock_with_ref.incRef();
      VLOG(5) << "The ref count of server " << key << " increase to " << ref_cnt
              << ".";

      return sock_with_ref.getServerSocket();
    }

    ServerSocketWithRef new_sock(
        std::make_shared<ServerSocket>(host, port, key));
    sock_map_.insert(std::make_pair(key, std::move(new_sock)));

    VLOG(3) << "Create server socket, socket key " << key << ".";
    auto &sock_with_ref = sock_map_[key];
    uint16_t ref_cnt = sock_with_ref.incRef();
    VLOG(5) << "The ref count of server " << key << " increase to " << ref_cnt
            << ".";
    return sock_with_ref.getServerSocket();
  }

  void destroyServerSocket(const std::string &host, const uint16_t port) {
    std::string key = "server_" + host + "_" + std::to_string(port);
    std::lock_guard<std::mutex> lock(mu_);
    auto iter = sock_map_.find(key);
    if (iter == sock_map_.end()) {
      LOG(ERROR) << "Can't find server socket with key " << key << ".";
      return;
    }

    auto &sock_with_ref = iter->second;
    if (sock_with_ref.decRef() == 0) {
      VLOG(3) << "Destroy server socket, socket key " << key << ".";
      sock_map_.erase(iter);
    } else {
      VLOG(5) << "Ref count of server " << key << " decrease to "
              << sock_with_ref.getRef() << ".";
    }
  };

private:
  class ServerSocketWithRef {
  public:
    ServerSocketWithRef() {
      sock_ = nullptr;
      ref_cnt_.store(0);
    }

    ServerSocketWithRef(std::shared_ptr<ServerSocket> sock) {
      sock_ = sock;
      ref_cnt_.store(0);
    }

    std::shared_ptr<ServerSocket> getServerSocket(void) { return sock_; }

    ServerSocketWithRef(ServerSocketWithRef &&sock) {
      this->ref_cnt_.store(sock.ref_cnt_.load());
      this->sock_ = sock.sock_;
      sock.ref_cnt_.store(0);
      sock.sock_ = nullptr;
    }

    uint16_t incRef(void) { return ref_cnt_ += 1; }

    uint16_t decRef(void) { return ref_cnt_ -= 1; }

    uint16_t getRef(void) { return ref_cnt_.load(); }

    std::shared_ptr<ServerSocket> sock_;
    std::atomic<uint16_t> ref_cnt_;
  };

  std::mutex mu_;
  std::map<std::string, ServerSocketWithRef> sock_map_;
};

ServerSocketManager serverManager;

class ClientSocket : public NamedSocket {
public:
  ClientSocket(const std::string &host, const uint16_t port,
               const std::string &tag)
      : NamedSocket(host, port, tag) {
    VLOG(3) << "Init client socket, tag " << tag_ << ", server addr " << host_
            << ":" << port << ".";
  }

  ~ClientSocket() {
    valid_flag_.store(false);
    recv_loop_.join();
    close(fd_);
    host_.clear();
    tag_.clear();
    port_ = 0;
  }

  Status allocBufferForFill(__attribute__((unused)) const std::string &tag,
                            uint16_t &buff_index) {
    NetworkBuffer *buff = nullptr;
    return recv_buf_.getBufferForFill(buff_index, &buff);
  }

  Status allocBufferForRead(__attribute__((unused)) const std::string &tag,
                            uint16_t &buff_index) {
    NetworkBuffer *buff = nullptr;
    return recv_buf_.getBufferForRead(buff_index, &buff);
  }

  Status freeBuffer(__attribute__((unused)) const std::string &tag,
                    const uint16_t buff_index) {
    NetworkBuffer *buff = nullptr;
    recv_buf_.putBuffer(buff_index);
    return Status::OK();
  }

  Status sendMessageWithTag(void *ptr, size_t send_size) {
    if (!valid_flag_.load()) {
      LOG(ERROR) << "Invalid client socket, forbid send operation.";
      return Status::InvalidError();
    }

    VLOG(5) << "Send message with fd " << fd_ << ".";

    uint32_t u32_size = send_size;
    ssize_t send_bytes = writen(fd_, &u32_size, sizeof(u32_size));
    if (send_bytes != sizeof(u32_size)) {
      close(fd_);
      valid_flag_.store(false);
      LOG(ERROR) << "Send message size failed, tag " << tag_ << ".";
      return Status::NetworkError();
    }

    send_bytes = writen(fd_, ptr, send_size);
    if (send_bytes != static_cast<ssize_t>(send_size)) {
      close(fd_);
      valid_flag_.store(false);
      LOG(ERROR) << "Send message failed, message size " << send_size
                 << ", tag " << tag_ << ".";
      return Status::NetworkError();
    }

    return Status::OK();
  }

  Status getMessageWithTag(const uint16_t index, std::string &container,
                           uint16_t timeout) {
    if (!valid_flag_.load()) {
      LOG(ERROR) << "Invalid client socket, forbid recv operation.";
      return Status::InvalidError();
    }

    NetworkBuffer *buf = nullptr;
    auto status = recv_buf_.getBufferWithIndex(index, &buf);
    if (!status.IsOK()) {
      LOG(ERROR) << "Get buffer with index " << index << " failed, tag " << tag_
                 << ".";
      return Status::InvalidError();
    }

    // Default timeout is 5 minutes.
    void *ret_ptr = nullptr;
    size_t ret_size = 0;
    status = buf->consumeBuffer(&ret_ptr, ret_size, timeout);
    if (!status.IsOK()) {
      LOG(ERROR) << "Get message with tag " << tag_ << " and index " << index
                 << " failed, timeout.";

      recv_buf_.putBuffer(index);
      return Status::TimeoutError();
    }

    container.resize(ret_size);
    memcpy(reinterpret_cast<uint8_t *>(container.data()),
           reinterpret_cast<uint8_t *>(ret_ptr), ret_size);

    recv_buf_.putBuffer(index);
    ret_ptr = nullptr;
    ret_size = 0;

    VLOG(5) << "Free buffer, index " << index << ", tag " << tag_ << ".";
    VLOG(5) << "Get message with tag " << tag_ << " finish, message size "
            << container.size() << ".";

    return Status::OK();
  }

  Status getMessageWithTag(const uint16_t index, void *ptr, size_t recv_size,
                           uint16_t timeout) {
    if (!valid_flag_.load()) {
      LOG(ERROR) << "Invalid client socket, forbid recv operation.";
      return Status::InvalidError();
    }

    NetworkBuffer *buf = nullptr;
    auto status = recv_buf_.getBufferWithIndex(index, &buf);
    if (!status.IsOK()) {
      LOG(ERROR) << "Get buffer with index " << index << " failed, tag " << tag_
                 << ".";
      return Status::InvalidError();
    }

    buf->provideBuffer(ptr, recv_size);

    // Default timeout is 5 minutes.
    void *ret_ptr = nullptr;
    size_t ret_size = 0;
    status = buf->consumeBuffer(&ret_ptr, ret_size, timeout);
    if (!status.IsOK()) {
      LOG(ERROR) << "Get message with tag " << tag_ << " and index " << index
                 << " failed, timeout.";

      recv_buf_.putBuffer(index);
      return Status::TimeoutError();
    }

    assert(ret_ptr == ptr);
    assert(ret_size == recv_size);

    recv_buf_.putBuffer(index);

    VLOG(5) << "Free buffer, index " << index << ", tag " << tag_ << ".";
    VLOG(5) << "Get message with tag " << tag_ << " finish, message size "
            << recv_size << ".";

    return Status::OK();
  }

  Status initSocket(void) {
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ == -1) {
      LOG(ERROR) << "Run socket failed, " << strerror(errno) << ".";
      return Status::SyscallError();
    }

    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(host_.c_str());
    server_addr.sin_port = htons(port_);

    int ret =
        connect(fd_, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
    if (ret == -1) {
      LOG(ERROR) << "Connect to " << host_ << ":" << port_ << " failed, "
                 << strerror(errno) << ".";
      close(fd_);
      return Status::SyscallError();
    }

    size_t send_size = tag_.size() + sizeof(uint32_t);
    std::vector<char> send_msg;
    send_msg.resize(send_size);
    uint32_t *ptr = reinterpret_cast<uint32_t *>(send_msg.data());
    *ptr = tag_.size();

    char *tag_ptr = reinterpret_cast<char *>(ptr + 1);
    memcpy(tag_ptr, tag_.c_str(), tag_.size());

    ssize_t send_bytes = writen(fd_, send_msg.data(), send_size);
    if (send_bytes != static_cast<ssize_t>(send_size)) {
      LOG(ERROR) << "Send tag to server failed, message size " << send_size
                 << ", tag " << tag_ << ".";
      return Status::SyscallError();
    }

    valid_flag_.store(true);

    VLOG(3) << "Init client socket finish, tag " << tag_ << ".";
    return Status::OK();
  }

  Status startRecvLoop(void) {
    recv_loop_ = std::thread(&ClientSocket::recvLoop, this);
    return Status::OK();
  }

private:
  void recvLoop(void) {
    bool errors = false;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100;

    while (valid_flag_.load() == true) {
      fd_set read_fds;
      FD_ZERO(&read_fds);
      FD_SET(fd_, &read_fds);

      fd_set exception_fds;
      FD_ZERO(&exception_fds);
      FD_SET(fd_, &exception_fds);

      int ret = select(fd_ + 1, &read_fds, nullptr, &exception_fds, &tv);
      if (ret == 0)
        continue;

      if (ret == -1) {
        errors = true;
        LOG(ERROR) << "Run select failed, " << strerror(errno) << ".";
        break;
      }

      if (FD_ISSET(fd_, &exception_fds)) {
        close(fd_);
        errors = true;
        LOG(ERROR) << "Close client socket due to error.";
        break;
      }

      uint32_t msg_size = 0;
      ssize_t read_bytes = readn(fd_, &msg_size, sizeof(uint32_t));
      if (read_bytes != sizeof(uint32_t)) {
        if (read_bytes == 0) {
          close(fd_);
          break;
        }

        close(fd_);
        errors = true;
        LOG(ERROR) << "Recv message size failed.";
        break;
      }

      VLOG(5) << "Size of recv msg is " << msg_size << ", tag " << tag_ << ".";

      NetworkBuffer *buffer = nullptr;
      uint16_t index = 0;
      auto status = recv_buf_.getBufferForFill(index, &buffer);
      if (!status.IsOK()) {
        close(fd_);
        errors = true;
        LOG(ERROR) << "Get recv buffer failed, tag " << tag_ << ".";
        break;
      }

      VLOG(5) << "Allocate buffer for fill, message size " << msg_size
              << ", index " << index << ", tag " << tag_ << ".";

      void *ptr = nullptr;
      buffer->initBuffer(msg_size);
      buffer->getBufferPtr(msg_size, &ptr);

      read_bytes = readn(fd_, ptr, msg_size);
      if (read_bytes != msg_size) {
        if (read_bytes == 0) {
          close(fd_);
          break;
        }

        close(fd_);
        errors = true;
        LOG(ERROR) << "Recv message failed, message size " << msg_size
                   << ", tag " << tag_ << ".";
        break;
      }

      buffer->putBufferPtr(ptr);
    }

    if (errors)
      LOG(ERROR) << "Client recv loop exist due to error.";
    else if (valid_flag_.load() == false)
      VLOG(3) << "Client recv loop exist due to stop signal.";
    else
      VLOG(3) << "Client recv loop exist due to peer close.";
  }

  int fd_{0};

  std::thread recv_loop_;
  std::atomic<bool> valid_flag_{false};

  MultipleNetworkBuffer recv_buf_;
};

class ClientSocketManager {
public:
  std::shared_ptr<NamedSocket> getOrCreateClientSocket(const std::string &host,
                                                       const uint16_t port,
                                                       const std::string &tag) {
    std::lock_guard<std::mutex> lock(mu_);
    auto iter = sock_map_.find(tag);
    if (iter != sock_map_.end())
      return std::dynamic_pointer_cast<NamedSocket>(iter->second);

    sock_map_.insert(
        std::make_pair(tag, std::make_shared<ClientSocket>(host, port, tag)));
    return std::dynamic_pointer_cast<NamedSocket>(sock_map_[tag]);
  }

  void destroyClientSocket(const std::string &tag) {
    std::lock_guard<std::mutex> lock(mu_);
    auto iter = sock_map_.find(tag);
    if (iter != sock_map_.end())
      sock_map_.erase(iter);
  }

private:
  std::mutex mu_;
  std::map<std::string, std::shared_ptr<ClientSocket>> sock_map_;
};

ClientSocketManager clientManager;
} // namespace

NamedSocket::NamedSocket(const std::string &host, const uint16_t port,
                         const std::string &tag) {
  host_ = host;
  port_ = port;
  tag_ = tag;
}

Status NamedSocket::startRecvLoop(void) { return Status::NotImplementError(); }

Status NamedSocket::initSocket(void) { return Status::NotImplementError(); }

Status NamedSocket::sendMessageWithTag(void *ptr, size_t size) {
  return Status::NotImplementError();
}

Status NamedSocket::startServerLoop(void) {
  return Status::NotImplementError();
}

Status NamedSocket::sendMessageWithTag(void *ptr, size_t size,
                                       const std::string &tag) {
  return Status::NotImplementError();
}

Status NamedSocket::getMessageWithTag(const uint16_t buff_index, void *ptr,
                                      size_t size, const std::string &tag,
                                      uint16_t timeout) {
  return Status::NotImplementError();
}

Status NamedSocket::getMessageWithTag(const uint16_t buff_index,
                                      std::string &container,
                                      const std::string &tag,
                                      uint16_t timeout) {
  return Status::NotImplementError();
}

Status NamedSocket::getMessageWithTag(const uint16_t buff_index,
                                      std::string &container,
                                      uint16_t timeout) {
  return Status::NotImplementError();
}

Status NamedSocket::getMessageWithTag(const uint16_t buff_index, void *ptr,
                                      size_t size, uint16_t timeout) {
  return Status::NotImplementError();
}

Status NamedSocket::allocBufferForFill(const std::string &tag,
                                       uint16_t &buff_index) {
  return Status::NotImplementError();
}

Status NamedSocket::allocBufferForRead(const std::string &tag,
                                       uint16_t &buff_index) {
  return Status::NotImplementError();
}

Status NamedSocket::freeBuffer(const std::string &tag,
                               const uint16_t buff_index) {
  return Status::NotImplementError();
}

ServerChannel::ServerChannel(const std::string &host, const uint16_t port,
                             const std::string &tag) {
  host_ = host;
  port_ = port;
  tag_ = tag;
  num_fork_ = 0;
}

std::string ServerChannel::getTag(void) { return tag_; }

Status ServerChannel::initChannel(void) {
  sock_ = serverManager.getOrCreateServerSocket(host_, port_);
  auto status = sock_->startServerLoop();
  return status;
}

ServerChannel::~ServerChannel() {
  forked_channel_.clear();
  serverManager.destroyServerSocket(host_, port_);
  VLOG(5) << "Destroy server channel, tag " << tag_ << ".";
}

std::future<Status> ServerChannel::asyncRecv(void *ptr, size_t recv_size) {
  uint16_t index = 0;
  sock_->allocBufferForRead(tag_, index);

  VLOG(5) << "[ServerChannel] Allocate buffer for read, recv size " << recv_size
          << ", index " << index << ", tag " << tag_ << ".";

  auto recv_fn = [this, index, ptr, recv_size]() -> Status {
    return sock_->getMessageWithTag(index, ptr, recv_size, tag_);
  };

  return std::async(recv_fn);
}

Status ServerChannel::recvResize(std::string &container) {
  uint16_t index = 0;
  sock_->allocBufferForRead(tag_, index);

  VLOG(5) << "[ServerChannel] Allocate buffer for read, recv size unknown"
          << ", index " << index << ", tag " << tag_ << ".";

  auto status = sock_->getMessageWithTag(index, container, tag_);
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv message with tag " << tag_
               << " failed, message size unknown.";
    return status;
  }

  VLOG(5) << "Recv and resize message with tag " << tag_
          << " finish, message size " << container.size() << ".";

  return status;
}

std::future<Status> ServerChannel::asyncSend(void *ptr, size_t send_size) {
  auto send_fn = [this, ptr, send_size]() -> Status {
    return sock_->sendMessageWithTag(ptr, send_size, tag_);
  };

  return std::async(send_fn);
}

std::string ServerChannel::deriveNewTag(void) {
  num_fork_++;
  std::string new_tag = tag_ + "_fork_" + std::to_string(num_fork_);
  return new_tag;
}

std::shared_ptr<CryptoChannel> ServerChannel::fork(void) {
  std::string new_tag = deriveNewTag();
  std::shared_ptr<ServerChannel> new_channel =
      std::make_shared<ServerChannel>(host_, port_, new_tag);

  new_channel->num_fork_ = this->num_fork_;

  auto status = new_channel->initChannel();
  if (!status.IsOK())
    return nullptr;

  forked_channel_.emplace_back(new_channel);
  // return std::dynamic_pointer_cast<CryptoChannel>(new_channel);
  std::shared_ptr<CryptoChannel> ret =
      std::dynamic_pointer_cast<CryptoChannel>(new_channel);
  return ret;
}

ClientChannel::ClientChannel(const std::string &host, const uint16_t port,
                             const std::string &tag) {
  tag_ = tag;
  host_ = host;
  port_ = port;
  num_fork_ = 0;
}

Status ClientChannel::initChannel(void) {
  sock_ = clientManager.getOrCreateClientSocket(host_, port_, tag_);
  auto status = sock_->initSocket();
  if (!status.IsOK()) {
    LOG(ERROR) << "Init client socket failed.";
    return Status::InvalidError();
  }

  sock_->startRecvLoop();
  return Status::OK();
}

std::string ClientChannel::getTag(void) { return tag_; }

ClientChannel::~ClientChannel() {
  VLOG(5) << "Destroy client channel, tag " << tag_ << ".";
  forked_channel_.clear();
  clientManager.destroyClientSocket(tag_);
}

std::string ClientChannel::deriveNewTag(void) {
  num_fork_++;
  std::string new_tag = tag_ + "_fork_" + std::to_string(num_fork_);
  return new_tag;
}

std::shared_ptr<CryptoChannel> ClientChannel::fork(void) {
  std::string new_tag = deriveNewTag();
  std::shared_ptr<ClientChannel> new_channel =
      std::make_shared<ClientChannel>(host_, port_, new_tag);
  new_channel->num_fork_ = this->num_fork_;
  auto status = new_channel->initChannel();
  if (!status.IsOK())
    return nullptr;

  forked_channel_.emplace_back(new_channel);

  std::shared_ptr<CryptoChannel> ret =
      std::dynamic_pointer_cast<CryptoChannel>(new_channel);
  return ret;
  // return std::dynamic_pointer_cast<CryptoChannel>(new_channel);
}

std::future<Status> ClientChannel::asyncSend(void *ptr, size_t send_size) {
  VLOG(5) << "Send message, size " << send_size << ", tag " << tag_ << ".";

  auto send_fn = [this, ptr, send_size]() -> Status {
    return sock_->sendMessageWithTag(ptr, send_size);
  };

  return std::async(send_fn);
}

Status ClientChannel::recvResize(std::string &container) {
  uint16_t index = 0;
  sock_->allocBufferForRead(tag_, index);

  VLOG(5) << "[ClientChannel] Allocate buffer for read, recv size unknown"
          << ", index " << index << ", tag " << tag_ << ".";

  auto status = sock_->getMessageWithTag(index, container);
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv message with tag " << tag_
               << " failed, message size unknown.";
    return status;
  }

  VLOG(5) << "Recv and resize message with tag " << tag_
          << " finish, message size " << container.size() << ".";

  return status;
}

std::future<Status> ClientChannel::asyncRecv(void *ptr, size_t recv_size) {
  uint16_t index = 0;
  sock_->allocBufferForRead(tag_, index);

  VLOG(5) << "[ClientChannel] Allocate buffer for read, index " << index
          << ", tag " << tag_ << ", recv size " << recv_size << ".";

  auto recv_fn = [this, index, ptr, recv_size]() -> Status {
    return sock_->getMessageWithTag(index, ptr, recv_size);
  };

  return std::async(recv_fn);
}

} // namespace primihub::crypto::network
