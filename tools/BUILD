package(default_visibility = ["//visibility:public"])

cc_library(
  name = "crypto_channel",
  srcs = [
    "channel.cc",
  ],
  hdrs = [
    "channel.h",
    "status.h",
  ],
  deps = [
    "@ladnir_cryptoTools//:libcryptoTools",
    "@com_github_glog_glog//:glog",
    "@ph_communication//network:channel_interface",
  ]
)

cc_library(
  name = "socket_channel",
  srcs = [
    "socket.cc",
  ],
  hdrs = [
    "socket.h",
  ],
  copts = ["-fPIC"],
  deps = [
    ":crypto_channel",
    "@com_github_glog_glog//:glog"
  ],
)
