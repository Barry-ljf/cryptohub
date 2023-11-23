package(default_visibility = ["//visibility:public"])

cc_library(
  name = "ldpc",
  srcs = [
    "ldpcencoder.cpp",
    "ldpcdecoder.cpp",
    "ldpcimpulsedist.cpp",
    "ldpcsampler.cpp",
    "mtx.cpp",
    "util.cpp",
  ],
  hdrs = [
    "ldpcdecoder.h",
    "ldpcencoder.h",
    "ldpcimpulsedist.h",
    "ldpcsampler.h",
    "mtx.h",
    "util.h",
  ],
  deps = [
    "//psi/ot/tools:ot_tools",
    "@ladnir_cryptoTools//:libcryptoTools", 
  ],
)
