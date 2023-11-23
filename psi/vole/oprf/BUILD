package(default_visibility = ["//visibility:public"])

cc_library(
  name = "vole_rsopprf",
  hdrs = [
    "rsopprf.h",
    "rsoprf.h",
  ],
  srcs = [
    "rsopprf.cc"
  ],
  deps = [
    "//psi/okvs:simpleindex",
    "//psi/ot/vole/silent:vole",
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)

cc_library(
  name = "vole_rsoprf",
  hdrs = [
    "rsoprf.h",
  ],
  srcs = [
    "rsoprf.cc"
  ],
  deps = [
    "//psi/okvs:simpleindex",
    ":vole_rsopprf",
    "//psi/ot/vole/silent:vole",
    "@com_github_glog_glog//:glog",
    "@ladnir_cryptoTools//:libcryptoTools",
  ],
)