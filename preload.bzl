load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

def mycrypto_preload(): 
  if "rules_cc" not in native.existing_rules():
    http_archive(
      name = "rules_cc",
      urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.1/rules_cc-0.0.1.tar.gz"],
      sha256 = "4dccbfd22c0def164c8f47458bd50e0c7148f3d92002cdb459c2a96a68498241",
    )

  if "rules_foreign_cc" not in native.existing_rules():
    http_archive(
      name = "rules_foreign_cc",
      sha256 = "6041f1374ff32ba711564374ad8e007aef77f71561a7ce784123b9b4b88614fc",
      strip_prefix = "rules_foreign_cc-0.8.0",
      url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.8.0.tar.gz",
    )
  
  if "rules_proto" not in native.existing_rules():
    http_archive(
      name = "rules_proto",
      sha256 = "e017528fd1c91c5a33f15493e3a398181a9e821a804eb7ff5acdd1d2d6c2b18d",
      strip_prefix = "rules_proto-4.0.0-3.20.0",
      urls = [
        "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0-3.20.0.tar.gz",
      ],
    )

  if "com_github_nelhage_rules_boost" not in native.existing_rules():
    git_repository(
      name = "com_github_nelhage_rules_boost",
      # commit = "1e3a69bf2d5cd10c34b74f066054cd335d033d71",
      branch = "master",
      remote = "https://github.com/primihub/rules_boost.git",
      # shallow_since = "1591047380 -0700",
    )

  if "ladnir_cryptoTools" not in native.existing_rules():
    git_repository(
      name = "ladnir_cryptoTools",
      branch = "volepsi_deps",
      remote = "https://github.com/Keepmoving-ZXY/cryptoTools.git",
    )

  if "sparsehash" not in native.existing_rules():
    git_repository(
      name = "sparsehash",
      branch = "volepsi_dep",
      remote = "https://github.com/Barry-ljf/sparsehash-c11.git",
    )


