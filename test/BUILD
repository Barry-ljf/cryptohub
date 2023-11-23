package(default_visibility = ["//visibility:public"])

cc_test(
  name = "test_distributed_sm2_signature",
  srcs = [
    "distributed_signer_test.cc",
  ],
  deps = [
    "//sm2:distributed_sm2_signature",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_socket",
  srcs = [
    "socket_test.cc",
  ],
  deps = [
    "//tools:socket_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_pprf",
  srcs = [
    "pprf_test.cc",
  ],
  deps = [
    "//psi/ot/tools:silentpprf",
    "@ph_communication//network:mem_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog",
  ],
)

cc_test(
  name = "test_baseot",
  srcs = [
    "baseot_test.cc",
  ],
  deps = [
    "//psi/ot/base:baseot",
    "@ph_communication//network:mem_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_softspokenot",
  srcs = [
    "softspoken_test.cc",
    "ot_tests.cc",
    "ot_tests.h",
  ],
  deps = [
    "//psi/ot/twochooseone/softspokenot:softspokenot",
    "@ph_communication//network:mem_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ]
)

cc_test(
  name = "test_iknp",
  srcs = [
    "iknp_test.cc",
    "ot_tests.cc",
    "ot_tests.h",
  ],
  deps = [
    "//psi/ot/twochooseone/iknp:iknpot",
    "@ph_communication//network:mem_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_silentot",
  srcs = [
    "silent_test.cc",
  ],
  deps = [
    "//psi/ot/twochooseone/silent:silentotext",
    "@ph_communication//network:mem_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_vole",
  srcs = [
    "vole_test.cc",
  ],
  deps = [
    "//psi/ot/vole/noisy:noisyvole",
    "//psi/ot/vole/silent:vole",
    "@ph_communication//network:mem_channel",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_library(
  name = "heading_rspsi",
  srcs = [
    "rsopprf_tests.h",
    "rsoprf_tests.h",
    "rspsi_tests.h",
  ],
  deps = [
    "//psi/vole/oprf:vole_rsopprf",
    "//psi/vole/oprf:vole_rsoprf",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@com_github_glog_glog//:glog"
  ],
)


cc_test(
  name = "test_rsoprf",
  srcs = [
    "rsoprf_tests.cc",
  ],
  deps = [
    ":heading_rspsi",
    "//psi/okvs:simpleindex",
    "//psi/vole/oprf:vole_rsopprf",
    "//psi/vole/oprf:vole_rsoprf",
    "@ph_communication//network:mem_channel",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_rsopprf",
  srcs = [
    "rsopprf_tests.cc",
  ],
  deps = [
    ":heading_rspsi",
    "//psi/vole/oprf:vole_rsopprf",
    "//psi/vole/oprf:vole_rsoprf",
    "@ph_communication//network:mem_channel",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)

cc_test(
  name = "test_rspsi",
  srcs = [
    "rspsi_tests.cc",
  ],
  deps = [
    ":heading_rspsi",
    "//psi/vole/oprf:vole_rsoprf",
    "//psi/vole/psi:vole_rspsi",
    "@ph_communication//network:mem_channel",
    "@ladnir_cryptoTools//:libcryptoTools",
    "@com_google_googletest//:gtest_main",
    "@com_github_glog_glog//:glog"
  ],
)
