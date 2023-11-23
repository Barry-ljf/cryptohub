package(default_visibility = ["//visibility:public"])

cc_library(
  name = "subspacevole",
  srcs = [
    "smallfieldvole.cpp",
  ],
  hdrs = [
    "subspacevole.h",
    "smallfieldvole.h",
    "subspacevolemaliciousleaky.h",
  ],
  deps = [
    "//psi/ot/twochooseone:otdefine",
    "//psi/ot/tools:encoder",
    "//psi/ot/tools:silentpprf",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@ph_communication//network:channel_interface",
  ]
)
