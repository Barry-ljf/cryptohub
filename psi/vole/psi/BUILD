package(default_visibility = ["//visibility:public"])

cc_library(
  name = "vole_rspsi", 
  srcs = ["rspsi.cc"],
  hdrs =
  [
    "rspsi.h",
  ],
  deps = [
  "//psi/okvs:simpleindex", "//psi/okvs:okvs", "//psi/vole/oprf:vole_rsoprf",
  "@com_github_glog_glog//:glog", "@sparsehash//sparsehash:dense_hash_lib"
])