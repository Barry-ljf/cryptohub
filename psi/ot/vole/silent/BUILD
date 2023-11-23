package(default_visibility = ["//visibility:public"])

cc_library(
  name = "vole",
  srcs = [
    "silentvolereceiver.cpp",
    "silentvolesender.cpp",
  ],
  hdrs = [
    "silentvolereceiver.h",
    "silentvolesender.h",
  ],
  deps = [
    "//psi/ot/base:otinterface",
    "//psi/ot/base:baseot",
    "//psi/ot/tools:silentpprf",
    "//psi/ot/twochooseone:otdefine",
    "//psi/ot/twochooseone/softspokenot:softspokenot",
    "//psi/ot/vole/noisy:noisyvole",
    "//psi/ot/twochooseone/iknp:iknpot",
    "//psi/ot/twochooseone/silent:silentotext",
    "//psi/ot/tools/ldpc:ldpc",
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
  ]
)


