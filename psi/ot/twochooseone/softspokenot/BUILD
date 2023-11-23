package(default_visibility = ["//visibility:public"])

cc_library(
  name = "softspokenot",
  srcs = [
    "softspokenshotext.cpp",
    "softspokenmalotext.cpp",
  ],
  hdrs = [
    "softspokenmalotext.h",
    "softspokenshotext.h",
  ],
  deps = [
    "//psi/ot/base:otextinterface",
    "//psi/ot/vole/softspokenot:subspacevole",
    "//psi/ot/tools:ot_tools",
    "//psi/ot/tools:repetitioncode",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
  ],
)
