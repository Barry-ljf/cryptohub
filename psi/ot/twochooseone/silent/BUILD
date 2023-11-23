package(default_visibility = ["//visibility:public"])

cc_library(
  name = "silentotext",
  srcs = [
    "silentotextreceiver.cpp",
    "silentotextsender.cpp",
  ],
  hdrs = [
    "silentotextreceiver.h",
    "silentotextsender.h"
  ],
  deps = [
    "//psi/ot/base:baseot",
    "//psi/ot/base:otextinterface",
    "//psi/ot/twochooseone/softspokenot:softspokenot",
    "//psi/ot/twochooseone:otdefine",
    "//psi/ot/vole/noisy:noisyvole",
    "//psi/ot/tools/ldpc:ldpc",
    "@ph_communication//network:channel_interface",
    "@ladnir_cryptoTools//:libcryptoTools", 
  ],
)
