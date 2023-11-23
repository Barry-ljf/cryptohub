load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
  name = "distributed_signature_proto",
  srcs = [":distributed_signature.proto"],
)

cc_proto_library(
  name = "distributed_signature_cc_proto",
  deps = [":distributed_signature_proto"],
)
