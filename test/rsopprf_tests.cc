#include "test/rsopprf_tests.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <iomanip>

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"
#include "network/mem_channel.h"
#include "psi/vole/oprf/rsopprf.h"
#include "psi/vole/oprf/rsoprf.h"

//#include "Common.h"

using primihub::link::Channel;
using primihub::link::MemoryChannel;
using ChannelRole = MemoryChannel::ChannelRole;

using namespace oc;
namespace primihub::crypto {

// void RsOpprf_eval_blk_test() {
TEST(RsOpprfTest, RsOpprfEvalBlk) {
  RsOpprfSender sender;
  RsOpprfReceiver recver;

  // auto sockets = cp::LocalAsyncSocket::makePair();

  using Channel = primihub::link::Channel;

  // cp::BufferingSocket chls[2];
  std::shared_ptr<MemoryChannel> channel_impl1 =
      std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
  std::shared_ptr<Channel> channel1 =
      std::make_shared<Channel>(channel_impl1, "RsOpprfEvalBlk");

  std::shared_ptr<MemoryChannel> channel_impl2 =
      std::make_shared<MemoryChannel>(ChannelRole::SERVER);
  std::shared_ptr<Channel> channel2 =
      std::make_shared<Channel>(channel_impl2, "RsOpprfEvalBlk");

  u64 n = 5;
  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  std::vector<block> vals(n), out(n), recvOut(n);

  prng0.get(vals.data(), n);
  prng0.get(out.data(), n);

  for (auto vals_item : vals) {
    std::cout << vals_item << "vals_item\n";
  }
  for (auto out_item : out) {
    std::cout << out_item << "out_item\n";
  }

  for (auto recvOut_item : recvOut) {
    std::cout << recvOut_item << "recvOut_item\n";
  }

  auto p0_send = [&sender, &n, &vals, &out, &prng0, channel1]() {
    sender.send(n, vals, out, prng0, 1, channel1);
  };
  auto p1_recv = [&recver, &n, &vals, &recvOut, &prng1, channel2]() {
    recver.receive(n, vals, recvOut, prng1, 1, channel2);
  };

  auto send_task = std::async(p0_send);
  auto recv_task = std::async(p1_recv);

  for (auto recvOut_item : recvOut) {
    std::cout << recvOut_item << "out: recvOut_item\n";
  }

  send_task.get();
  recv_task.get();

  for (auto recvOut_item : recvOut) {
    std::cout << recvOut_item << "recvOut_item\n";
  }
  // auto p0 = sender.send(n, vals, out, prng0, 1, sockets[0]);
  // auto p1 = recver.receive(n, vals, recvOut, prng1, 1, sockets[1]);

  // eval(p0, p1);

  u64 count = 0;
  for (u64 i = 0; i < n; ++i) {
    auto v = sender.eval<block>(vals[i]);
    if (recvOut[i] != v || recvOut[i] != out[i]) {
      if (count < 10)
        std::cout << i << " recv= " << recvOut[i] << ", send = " << v
                  << ", send* = " << out[i] << std::endl;
      else
        break;

      ++count;
    }
  }
  if (count) throw RTE_LOC;
}

template <typename Vec>
std::string hex(const Vec& v) {
  auto d = (u8*)v.data();
  auto s = v.size() * sizeof(typename Vec::value_type);
  std::stringstream ss;
  for (u64 i = 0; i < s; ++i)
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
  return ss.str();
}

// // void RsOpprf_eval_blk_mtx_test() {
// TEST(RsOpprfTest, RsOpprfEvalBlkMtx) {
//   RsOpprfSender sender;
//   RsOpprfReceiver recver;

//   // auto sockets = cp::LocalAsyncSocket::makePair();
//   using Channel = primihub::link::Channel;

//   // cp::BufferingSocket chls[2];
//   std::shared_ptr<MemoryChannel> channel_impl1 =
//       std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
//   std::shared_ptr<Channel> channel1 =
//       std::make_shared<Channel>(channel_impl1, "RsOpprfEvalBlkMtx");

//   std::shared_ptr<MemoryChannel> channel_impl2 =
//       std::make_shared<MemoryChannel>(ChannelRole::SERVER);
//   std::shared_ptr<Channel> channel2 =
//       std::make_shared<Channel>(channel_impl2, "RsOpprfEvalBlkMtx");

//   u64 n = 4000;
//   u64 m = 7;
//   PRNG prng0(block(0, 0));
//   PRNG prng1(block(0, 1));

//   std::vector<block> vals(n);
//   oc::Matrix<block> out(n, m), out2(n, m), recvOut(n, m);

//   prng0.get(vals.data(), n);
//   prng0.get(out.data(), n);

//   auto p0_send = [&sender, &n, &vals, &out, &prng0, channel1]() {
//     sender.send(n, vals, out, prng0, 1, channel1);
//   };
//   auto p1_recv = [&recver, &n, &vals, &recvOut, &prng1, channel2]() {
//     recver.receive(n, vals, recvOut, prng1, 1, channel2);
//   };

//   // auto p0 = sender.send(n, vals, out, prng0, 1, sockets[0]);
//   // auto p1 = recver.receive(n, vals, recvOut, prng1, 1, sockets[1]);
//   auto send_task = std::async(p0_send);
//   auto recv_task = std::async(p1_recv);

//   send_task.get();
//   recv_task.get();
//   // eval(p0, p1);

//   sender.eval(vals, out2, 1);

//   u64 count = 0;
//   for (u64 i = 0; i < n; ++i) {
//     auto c0 = memcmp(recvOut[i].data(), out[i].data(), m * sizeof(block)) !=
//     0; auto c1 = memcmp(recvOut[i].data(), out2[i].data(), m * sizeof(block))
//     != 0; if (c0 || c1) {
//       if (count < 10)
//         std::cout << i << "\n\t " << hex(recvOut[i]) << "\n\t " <<
//         hex(out2[i])
//                   << "\n\t " << hex(out[i]) << std::endl;
//       else
//         break;

//       ++count;
//     }
//   }
//   if (count) throw RTE_LOC;
// }

// // void RsOpprf_eval_u8_test() {
// TEST(RsOpprfTest, RsOpprfEvalU8) {
//   RsOpprfSender sender;
//   RsOpprfReceiver recver;

//   // auto sockets = cp::LocalAsyncSocket::makePair();

//   using Channel = primihub::link::Channel;

//   // cp::BufferingSocket chls[2];
//   std::shared_ptr<MemoryChannel> channel_impl1 =
//       std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
//   std::shared_ptr<Channel> channel1 =
//       std::make_shared<Channel>(channel_impl1, "RsOpprfEvalU8");

//   std::shared_ptr<MemoryChannel> channel_impl2 =
//       std::make_shared<MemoryChannel>(ChannelRole::SERVER);
//   std::shared_ptr<Channel> channel2 =
//       std::make_shared<Channel>(channel_impl2, "RsOpprfEvalU8");

//   u64 n = 4000;
//   PRNG prng0(block(0, 0));
//   PRNG prng1(block(0, 1));

//   std::vector<block> vals(n);
//   std::vector<u8> out(n), recvOut(n);

//   prng0.get(vals.data(), n);
//   prng0.get(out.data(), n);

//   //auto p0 = sender.send<u8>(n, vals, out, prng0, 1, sockets[0]);
//   // auto p1 = recver.receive<u8>(n, vals, recvOut, prng1, 1, sockets[1]);
//   auto p0_send = [&sender, &n, &vals, &out, &prng0, channel1]() {
//     sender.send<u8>(n, vals, out, prng0, 1, channel1);
//   };
//   auto p1_recv = [&recver, &n, &vals, &recvOut, &prng1, channel2]() {
//     recver.receive<u8>(n, vals, recvOut, prng1, 1, channel2);
//   };

//   // auto p0 = sender.send(n, vals, out, prng0, 1, sockets[0]);
//   // auto p1 = recver.receive(n, vals, recvOut, prng1, 1, sockets[1]);
//   auto send_task = std::async(p0_send);
//   auto recv_task = std::async(p1_recv);

//   send_task.get();
//   recv_task.get();
//   // eval(p0, p1);

//   u64 count = 0;
//   for (u64 i = 0; i < n; ++i) {
//     auto v = sender.eval<u8>(vals[i]);
//     if (recvOut[i] != v || recvOut[i] != out[i]) {
//       if (count < 10)
//         std::cout << i << " " << recvOut[i] << " " << v << " " << out[i]
//                   << std::endl;
//       else
//         break;

//       ++count;
//     }
//   }
//   if (count) throw RTE_LOC;
// }

// // void RsOpprf_eval_u8_mtx_test() {
// TEST(RsOpprfTest, RsOpprfEvalU8Mtx) {
//   RsOpprfSender sender;
//   RsOpprfReceiver recver;

//   // auto sockets = cp::LocalAsyncSocket::makePair();
//   using Channel = primihub::link::Channel;

//   // cp::BufferingSocket chls[2];
//   std::shared_ptr<MemoryChannel> channel_impl1 =
//       std::make_shared<MemoryChannel>(ChannelRole::CLIENT);
//   std::shared_ptr<Channel> channel1 =
//       std::make_shared<Channel>(channel_impl1, "RsOpprfEvalU8Mtx");

//   std::shared_ptr<MemoryChannel> channel_impl2 =
//       std::make_shared<MemoryChannel>(ChannelRole::SERVER);
//   std::shared_ptr<Channel> channel2 =
//       std::make_shared<Channel>(channel_impl2, "RsOpprfEvalU8Mtx");

//   u64 n = 4000;
//   u64 m = 7;
//   PRNG prng0(block(0, 0));
//   PRNG prng1(block(0, 1));

//   std::vector<block> vals(n);
//   oc::Matrix<u8> out(n, m), out2(n, m), recvOut(n, m);

//   prng0.get(vals.data(), n);
//   prng0.get(out.data(), n);

//   // auto p0 = sender.send(n, vals, out, prng0, 1, sockets[0]);
//   // auto p1 = recver.receive(n, vals, recvOut, prng1, 1, sockets[1]);

//   // eval(p0, p1);
//   auto p0_send = [&sender, &n, &vals, &out, &prng0, channel1]() {
//     sender.send(n, vals, out, prng0, 1, channel1);
//   };
//   auto p1_recv = [&recver, &n, &vals, &recvOut, &prng1, channel2]() {
//     recver.receive(n, vals, recvOut, prng1, 1, channel2);
//   };

//   auto send_task = std::async(p0_send);
//   auto recv_task = std::async(p1_recv);

//   send_task.get();
//   recv_task.get();

//   sender.eval(vals, out2, 1);

//   u64 count = 0;
//   for (u64 i = 0; i < n; ++i) {
//     auto c0 = memcmp(recvOut[i].data(), out[i].data(), m * sizeof(u8)) != 0;
//     auto c1 = memcmp(recvOut[i].data(), out2[i].data(), m * sizeof(u8)) != 0;
//     if (c0 || c1) {
//       if (count < 10)
//         std::cout << i << " " << hex(recvOut[i]) << " " << hex(out2[i]) << "
//         "
//                   << hex(out[i]) << std::endl;
//       else
//         break;

//       ++count;
//     }
//   }
//   if (count) throw RTE_LOC;
// }
}  // namespace primihub::crypto