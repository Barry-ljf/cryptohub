package(default_visibility = ["//visibility:public"])

cc_library(
  name = "ot_tools",
  hdrs = [
    "tools.h",
  ],
  srcs = [
    "tools.cpp",
  ],
  deps = [
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)

cc_library(
  name = "silentpprf",
  srcs = [
    "silentpprf.cpp",
  ],
  hdrs = [
    "silentpprf.h",
  ],
  deps = [
    ":ot_tools",
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
  ]
)

cc_library(
  name = "encoder",
  hdrs = [
    "genericlinearcode.h",
  ],
  deps = [
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)

cc_library(
  name = "repetitioncode",
  hdrs = [
    "repetitioncode.h", 
  ], 
  deps = [
    ":encoder",
  ],
)

cc_library(
  name = "defaultcurve",
  hdrs = [
    "defaultcurve.h",
  ],
  deps = [
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)
