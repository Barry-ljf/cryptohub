#include "tools/socket.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

using primihub::crypto::Status;
using primihub::crypto::network::ClientChannel;
using primihub::crypto::network::CryptoChannel;
using primihub::crypto::network::ServerChannel;

static std::string gen_random(uint32_t len) {
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  std::string tmp_s;
  tmp_s.reserve(len);

  for (uint32_t i = 0; i < len; ++i)
    tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

  return tmp_s;
}

TEST(ChannelTest, SimpleSendRecvTest) {
  std::string host("127.0.0.1");
  std::string tag("test_tag");

  std::shared_ptr<CryptoChannel> server_channel =
      std::dynamic_pointer_cast<CryptoChannel>(
          std::make_shared<ServerChannel>(host, 35056, tag));
  auto status = server_channel->initChannel();
  EXPECT_EQ(status.IsOK(), true);

  std::shared_ptr<CryptoChannel> client_channel =
      std::dynamic_pointer_cast<CryptoChannel>(
          std::make_shared<ClientChannel>(host, 35056, tag));
  status = client_channel->initChannel();
  EXPECT_EQ(status.IsOK(), true);

  {
    std::string recv_buf;
    recv_buf.resize(1024);

    std::string send_buf = gen_random(1024);
    auto recv_fut = server_channel->asyncRecv(recv_buf.data(), recv_buf.size());
    auto send_fut = client_channel->asyncSend(send_buf.data(), send_buf.size());

    auto send_status = recv_fut.get();
    auto recv_status = send_fut.get();

    EXPECT_EQ(recv_status.IsOK(), true);
    EXPECT_EQ(send_status.IsOK(), true);
    EXPECT_EQ(send_buf == recv_buf, true);
  }

  {
    std::string send_buf = gen_random(1024);
    std::string recv_buf;
    recv_buf.resize(1024);
    auto recv_fut = client_channel->asyncRecv(recv_buf.data(), recv_buf.size());
    auto send_fut = server_channel->asyncSend(send_buf.data(), send_buf.size());

    auto send_status = send_fut.get();
    auto recv_status = recv_fut.get();

    EXPECT_EQ(recv_status.IsOK(), true);
    EXPECT_EQ(send_status.IsOK(), true);
    EXPECT_EQ(send_buf == recv_buf, true);
  }
}

TEST(ChannelTest, ForkTest) {
  std::string host("127.0.0.1");
  std::string tag("test_tag");

  std::shared_ptr<ServerChannel> server_channel =
      std::make_shared<ServerChannel>(host, 35056, tag);
  auto status = server_channel->initChannel();
  EXPECT_EQ(status.IsOK(), true);

  std::shared_ptr<ClientChannel> client_channel =
      std::make_shared<ClientChannel>(host, 35056, tag);
  status = client_channel->initChannel();
  EXPECT_EQ(status.IsOK(), true);

  uint16_t fork_num = 10;
  std::vector<std::shared_ptr<CryptoChannel>> client_fork_channels;
  std::vector<std::shared_ptr<CryptoChannel>> server_fork_channels;

  for (uint16_t i = 0; i < fork_num; i++) {
    client_fork_channels.push_back(client_channel->fork());
    server_fork_channels.push_back(server_channel->fork());
  }

  std::string send_buf = gen_random(1024);
  auto send_fn = [&client_fork_channels, &send_buf]() {
    std::vector<std::future<Status>> send_futs;

    for (auto &channel : client_fork_channels)
      send_futs.push_back(channel->asyncSend(send_buf.data(), send_buf.size()));

    for (auto &fut : send_futs) EXPECT_EQ(fut.get().IsOK(), true);
  };

  auto recv_fn = [&server_fork_channels, &send_buf]() {
    std::vector<std::string> all_recv_buf;
    all_recv_buf.resize(server_fork_channels.size());
    for (auto &recv_buf : all_recv_buf) recv_buf.resize(1024);

    std::vector<std::future<Status>> recv_futs;
    for (size_t i = 0; i < server_fork_channels.size(); i++)
      recv_futs.push_back(server_fork_channels[i]->asyncRecv(
          all_recv_buf[i].data(), all_recv_buf[i].size()));

    for (auto &fut : recv_futs) EXPECT_EQ(fut.get().IsOK(), true);

    for (auto &recv_buf : all_recv_buf) EXPECT_EQ(recv_buf == send_buf, true);
  };

  std::future<void> recv_fut = std::async(recv_fn);
  std::future<void> send_fut = std::async(send_fn);

  send_fut.get();
  recv_fut.get();
}

TEST(channel_test, recv_resize_test) {
  std::string host("127.0.0.1");
  std::string tag("test_tag");

  std::shared_ptr<ServerChannel> server_channel =
      std::make_shared<ServerChannel>(host, 35056, tag);
  auto status = server_channel->initChannel();
  EXPECT_EQ(status.IsOK(), true);

  std::shared_ptr<ClientChannel> client_channel =
      std::make_shared<ClientChannel>(host, 35056, tag);
  status = client_channel->initChannel();
  EXPECT_EQ(status.IsOK(), true);

  std::string send_msg = gen_random(102400);
  std::string recv_msg{};

  auto send_fn = [client_channel, &send_msg]() {
    auto fut = client_channel->asyncSend(send_msg.data(), send_msg.size());
    auto status = fut.get();
    if (!status.IsOK()) LOG(ERROR) << "Send message failed.";
    return status;
  };

  auto recv_fn = [server_channel, &recv_msg]() {
    auto status = server_channel->recvResize(recv_msg);
    if (!status.IsOK()) LOG(ERROR) << "Run recvResize failed.";
    return status;
  };

  auto send_fut = std::async(send_fn);
  auto recv_fut = std::async(recv_fn);

  EXPECT_EQ(send_fut.get().IsOK(), true);
  EXPECT_EQ(recv_fut.get().IsOK(), true);
  EXPECT_EQ(recv_msg, send_msg);

  send_msg = gen_random(102400);
  recv_msg.clear();

  auto send_fn2 = [server_channel, &send_msg]() {
    auto fut = server_channel->asyncSend(send_msg.data(), send_msg.size());
    auto status = fut.get();
    if (!status.IsOK()) LOG(ERROR) << "Send message failed.";
    return status;
  };

  auto recv_fn2 = [client_channel, &recv_msg]() {
    auto status = client_channel->recvResize(recv_msg);
    if (!status.IsOK()) LOG(ERROR) << "Run recvResize failed.";
    return status;
  };

  auto send_fut2 = std::async(send_fn2);
  auto recv_fut2 = std::async(recv_fn2);
  EXPECT_EQ(send_fut2.get().IsOK(), true);
  EXPECT_EQ(recv_fut2.get().IsOK(), true);
  EXPECT_EQ(recv_msg, send_msg);
}
