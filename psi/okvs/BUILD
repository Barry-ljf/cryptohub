package(default_visibility = ["//visibility:public"])

cc_library(
  name = "okvs",
  hdrs = [
    "defines.h",
    "paxos.h",
    "pxutil.h",
    "paxosimpl.h",
    "libdivide.h"
  ],
  deps = [
    "//psi/ot/tools/ldpc:ldpc",
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)

cc_library(
  name = "simpleindex",
  srcs = ["simpleindex.cpp"],
  hdrs = [
    "simpleindex.h"
  ],
  deps = [
    ":okvs",
    "//psi/ot/tools/ldpc:ldpc",
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)

