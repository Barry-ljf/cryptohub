load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")
load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
load("@ladnir_cryptoTools//bazel:deps.bzl", "cryptoTools_deps")


def mycrypto_deps():
  if "com_github_gflags_gflags" not in native.existing_rules():
    http_archive(
      name = "com_github_gflags_gflags",
      sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
      strip_prefix = "gflags-2.2.2",
      urls = [
          "https://github.com/gflags/gflags/archive/v2.2.2.tar.gz",
      ],
    )

  if "com_github_glog_glog" not in native.existing_rules():
    http_archive(
      name = "com_github_glog_glog",
      strip_prefix = "glog-0.6.0",
      urls = ["https://primihub.oss-cn-beijing.aliyuncs.com/tools/glog-0.6.0.zip"],
    )

  if "com_google_googletest" not in native.existing_rules():
    http_archive(
      name = "com_google_googletest",
      urls = ["https://primihub.oss-cn-beijing.aliyuncs.com/tools/googletest-release-1.10.0.zip"],
      sha256 = "94c634d499558a76fa649edb13721dce6e98fb1e7018dfaeba3cd7a083945e91",
      strip_prefix = "googletest-release-1.10.0",
    )

  if "openssl" not in native.existing_rules():
    http_archive(
      name = "openssl",
      url = "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1o.tar.gz",
      strip_prefix = "openssl-OpenSSL_1_1_1o",
      build_file = "//third_party:openssl.BUILD",
    )

  if "github_com_span_lite" not in native.existing_rules():
    reference_index = ""
    http_archive(
      name = "github_com_span_lite",
      build_file = "//bazel:BUILD.span_lite",
      strip_prefix = "span-lite-0.10.3",
      urls = [
        "https://primihub.oss-cn-beijing.aliyuncs.com/tools/span-lite-0.10.3.tar.gz",
        "https://github.com/martinmoene/span-lite/archive/refs/tags/v0.10.3.tar.gz",
      ]
    )
  
  if "ph_communication" not in native.existing_rules():
    git_repository(
      name = "ph_communication",
      branch = "develop",
      remote = "https://github.com/primihub/communication.git",
    )

  
  cryptoTools_deps() 
  boost_deps()
  rules_proto_dependencies()
  rules_proto_toolchains()
  rules_foreign_cc_dependencies()
