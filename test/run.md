#test.cc:
#编译：
bazel build-- config =
linux_x86_64  // test:test_distributed_sm2_signature

#执行：
./
bazel -
bin / test / test_distributed_sm2_signature-- config = linux_x86_64

#调试：
bazel build-- compilation_mode = dbg-- config =
linux_x86_64  // test:test_distributed_sm2_signature
gdb./
bazel -
bin / test /
test_distributed_sm2_signature

#debug.cc:

#编译：
bazel build-- config =
linux_x86_64  // test:debug_distributed_sm2_signature

#执行：
./
bazel -
bin / test /
debug_distributed_sm2_signature-- config = linux_x86_64

#编译：
bazel build-- config =
linux_x86_64  // test:debug_distributed_sm2_signature

#执行：
./
bazel -
bin / test /
debug_distributed_sm2_signature-- config = linux_x86_64

#调试：
bazel build-- compilation_mode = dbg-- config =
linux_x86_64  // test:debug_distributed_sm2_signature
gdb./
bazel -
bin / test / debug_distributed_sm2_signature