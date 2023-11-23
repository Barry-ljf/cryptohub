package(default_visibility = ["//visibility:public"])

cc_library(
  name = "otinterface",
  srcs = [
    "otinterface.cpp",
  ],
  hdrs = [
    "otinterface.h",
  ],
  deps = [
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
  ]
)

cc_library(
  name = "baseot",
  srcs = [
    "simplestot.cpp"
  ],
  hdrs = [
    "baseot.h",
    "simplestot.h"
  ],
  deps = [
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
    "//psi/ot/base:otinterface",
    "//psi/ot/tools:defaultcurve"
  ]
)

cc_library(
  name = "otextinterface",
  srcs = [
    "otextinterface.cpp",
  ],
  hdrs = [
    "otextinterface.h",
  ],
  deps = [
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
    "//psi/ot/base:otinterface",
    "//psi/ot/base:baseot",
  ],
)


