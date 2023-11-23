package(default_visibility = ["//visibility:public"])

cc_library(
  name = "distributed_sm2_signature",
  srcs = [
    "distributed_sm2_pubkey.cc",
    "distributed_sm2_signer.cc",
    "distributed_sm2_verifier.cc",
  ],
  hdrs = [
    "distributed_sm2_pubkey.h",
    "distributed_sm2_signer.h",
    "distributed_sm2_verifier.h",
  ],
  deps = [
    "//proto:distributed_signature_cc_proto",
    "@com_github_glog_glog//:glog",
    "@openssl//:openssl",
  ],
)
