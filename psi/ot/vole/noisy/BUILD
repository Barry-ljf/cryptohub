package(default_visibility = ["//visibility:public"])

cc_library(
  name = "noisyvole",
  srcs = [
    "noisyvolereceiver.cpp",
    "noisyvolesender.cpp",
  ],
  hdrs = [
    "noisyvolereceiver.h",
    "noisyvolesender.h"
  ],
  deps = [
    "//psi/ot/base:otextinterface",
    "@ladnir_cryptoTools//:libcryptoTools", 
    "@ph_communication//network:channel_interface",
  ],
)
