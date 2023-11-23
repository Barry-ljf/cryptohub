#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <glog/logging.h>
#include <tuple>

#include "psi/ot/base/simplestot.h"
#include "psi/ot/tools/defaultcurve.h"

using namespace osuCrypto;

namespace primihub::crypto {
using Channel = primihub::link::Channel;
using namespace DefaultCurve;

void SimplestOT::receive(const BitVector &choices, span<block> msg, PRNG &prng,
                         std::shared_ptr<Channel> chl) {
  Curve curve;
  // MC_BEGIN(task<>, this, &choices, msg, &prng, &chl, n = u64{},
  //          buff = std::vector<u8>{},
  //          comm = std::array<u8, RandomOracle::HashSize>{}, seed = block{},
  //          b = std::vector<Number>{}, B = std::array<Point, 2>{}, A =
  //          Point{});
  u64 n = 0;
  std::vector<u8> buff{};
  std::array<u8, RandomOracle::HashSize> comm{};
  block seed{};
  std::vector<Number> b{};
  std::array<Point, 2> B{};
  Point A{};

  n = msg.size();

  buff.resize(Point::size + RandomOracle::HashSize * mUniformOTs);

  // MC_AWAIT(chl.recv(buff));
  auto fut = chl->asyncRecv(buff);
  auto status = fut.get();
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv content to buff failed.";
    throw std::runtime_error("Recv content to buff failed.");
  }

  Curve{};

  A.fromBytes(buff.data());

  if (mUniformOTs)
    memcpy(&comm, buff.data() + Point::size, RandomOracle::HashSize);

  buff.resize(Point::size * n);

  b.reserve(n);
  for (u64 i = 0; i < n; ++i) {
    b.emplace_back(prng);
    B[0] = Point::mulGenerator(b[i]);
    B[1] = A + B[0];

    B[choices[i]].toBytes(&buff[Point::size * i]);
  }

  // MC_AWAIT(chl.send(std::move(buff)));
  status = chl->asyncSend(std::move(buff));
  if (!status.IsOK()) {
    LOG(ERROR) << "Send content of buff failed.";
    throw std::runtime_error("Send content of buff failed.");
  }

  if (mUniformOTs) {
    // MC_AWAIT(chl.recv(seed));
    fut = chl->asyncRecv(seed);
    auto status = fut.get();
    if (!status.IsOK()) {
      LOG(ERROR) << "Recv seed failed.";
      throw std::runtime_error("Recv seed failed.");
    }

    RandomOracle ro;
    std::array<u8, RandomOracle::HashSize> comm2;
    ro.Update(seed);
    ro.Final(comm2);

    if (comm != comm2)
      throw std::runtime_error("bad decommitment " LOCATION);
  }

  Curve{};
  for (u64 i = 0; i < n; ++i) {
    B[0] = A * b[i];
    RandomOracle ro(sizeof(block));
    ro.Update(B[0]);
    ro.Update(i);
    if (mUniformOTs)
      ro.Update(seed);
    ro.Final(msg[i]);
  }
}

void SimplestOT::send(span<std::array<block, 2>> msg, PRNG &prng,
                      std::shared_ptr<Channel> chl) {
  using namespace DefaultCurve;
  Curve{};

  // MC_BEGIN(task<>, this, msg, &prng, &chl, n = u64{}, a = Number{}, A =
  // Point{},
  //          B = Point{}, buff = std::vector<u8>{}, seed = block{});

  u64 n = 0;
  Number a{};
  Point A{};
  Point B{};
  std::vector<u8> buff{};
  block seed{};

  Curve{};
  n = msg.size();

  a.randomize(prng);
  A = Point::mulGenerator(a);
  buff.resize(Point::size + RandomOracle::HashSize * mUniformOTs);
  A.toBytes(buff.data());

  if (mUniformOTs) {
    // commit to the seed
    seed = prng.get<block>();
    std::array<u8, RandomOracle::HashSize> comm;
    RandomOracle ro;
    ro.Update(seed);
    ro.Final(comm);
    memcpy(buff.data() + Point::size, comm.data(), comm.size());
  }

  // MC_AWAIT(chl.send(std::move(buff)));
  auto status = chl->asyncSend(std::move(buff));
  if (!status.IsOK()) {
    LOG(ERROR) << "Send content of buff failed.";
    throw std::runtime_error("Send content of buff failed.");
  }

  buff.resize(Point::size * n);
  // MC_AWAIT(chl.recv(buff));
  auto fut = chl->asyncRecv(buff);
  status = fut.get();
  if (!status.IsOK()) {
    LOG(ERROR) << "Recv content of buff failed.";
    throw std::runtime_error("Recv content of buff failed.");
  }

  if (mUniformOTs) {
    // decommit to the seed now that we have their messages.
    // MC_AWAIT(chl.send(std::move(seed)));
    auto status = chl->asyncSend(std::move(seed));
    if (!status.IsOK()) {
      LOG(ERROR) << "Send seed failed.";
      throw std::runtime_error("Send seed failed.");
    }
  }

  Curve{};
  A *= a;
  for (u64 i = 0; i < n; ++i) {
    B.fromBytes(&buff[Point::size * i]);

    B *= a;
    RandomOracle ro(sizeof(block));
    ro.Update(B);
    ro.Update(i);
    if (mUniformOTs)
      ro.Update(seed);
    ro.Final(msg[i][0]);

    B -= A;
    ro.Reset();
    ro.Update(B);
    ro.Update(i);
    if (mUniformOTs)
      ro.Update(seed);
    ro.Final(msg[i][1]);
  }
}
} // namespace primihub::crypto
