package(default_visibility = ["//visibility:public"])

cc_library(
  name = "iknpot",
  srcs = [
    "iknpotextreceiver.cpp",
    "iknpotextsender.cpp",
  ],
  hdrs = [
    "iknpotextreceiver.h",
    "iknpotextsender.h"
  ],
  deps = [
    "//psi/ot/base:otextinterface",
    "//psi/ot/tools:ot_tools",
    "//psi/ot/twochooseone:otdefine",
    "@ph_communication//network:channel_interface",
    "@ladnir_cryptoTools//:libcryptoTools", 
    "@com_github_glog_glog//:glog",
  ],
)
