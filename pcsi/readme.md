#### 1.CPU Instruction Set
The `PCSI-SUM` requires  many cpu instructions, they are `aes, sse2, sse3, sse4.1, pclmul, avx, avx2, bmi2`,  ensure the cpu of your workstation support these cpu instruction set.
#### 2.Compile dependencies
The base idea of this document is that compile and install dependencies into a custom directory, and we will fix this document to `/home/test/pcsi_deps/`, change the path to your own settings before run command.
##### 2.1 ABY
```
#### 2.4.boost
apt-get install libboost-all-dev
git clone https://github.com/encryptogroup/ABY.git
cd ABY
git reset --hard d8e69414d091cafc007e65a03ef30768ebaf723d
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/home/test/pcsi_deps/
make
make install
cd ..
cp build/extern/ENCRYPTO_utils/include/cmake_constants.h /home/test/pcsi_deps/include/ENCRYPTO_utils/
# change #include <cmake_constants.h> to #include "cmake_constants.h"
sed -i '24s/<cmake_constants.h>/"cmake_constants.h"/g' /home/test/pcsi_deps/include/ENCRYPTO_utils/constants.h
```
#### 2.2.libOTe
```
git clone https://github.com/osu-crypto/libOTe.git
cd libOTe
git reset --hard bc5c54e3007b2d147e4b9b9daa4bed4075244c50
git submodule update --init
python3 build.py -D ENABLE_CIRCUITS=ON ENABLE_RELIC=ON -D ENABLE_ALL_OT=ON --setup --boost --relic
python3 build.py -D ENABLE_CIRCUITS=ON ENABLE_RELIC=ON -D ENABLE_ALL_OT=ON --install=/home/test/pcsi_deps/
```
After run all commands above, edit `/home/test/pcsi_deps/include/cryptoTools/Common/block.h`, add below code to `line 302` then save:
```
inline block& operator^=(const block &rhs)
{
    *this = *this ^ rhs;
    return *this;
}
``` 
#### 2.3.HashingTables
```
git clone https://github.com/Oleksandr-Tkachenko/HashingTables.git
cd HashingTables
git reset --hard 78b8616531b0506569bc352e7355f554b5d276c7
mkdir build && cd build
cmake ..
make 
cp libHashingTables.a /home/test/pcsi_deps/lib/
cd ..
mkdir /home/test/pcsi_deps/include/HashingTables
mkdir -p /home/test/pcsi_deps/include/HashingTables/common
mkdir -p /home/test/pcsi_deps/include/HashingTables/cuckoo_hashing
mkdir -p /home/test/pcsi_deps/include/HashingTables/simple_hashing
cp common/*.h /home/test/pcsi_deps/include/HashingTables/common/
cp cuckoo_hashing/*.h /home/test/pcsi_deps/include/HashingTables/cuckoo_hashing/
cp simple_hashing/*.h /home/test/pcsi_deps/include/HashingTables/simple_hashing/
```
An error maybe generated when run `cmake ..` as below:
```
CMake Error at CMakeLists.txt:8 (if):
	if given arguments:
		"STREQUAL" "Release"
	Unknown arguments specified
``` 
This error is related to the version of `cmake`, and remove below code in `CMakeLists.txt`  in `HashingTables` will solve it:
```
if (${CMAKE_BUILD_TYPE} STREQUAL Release)
    message("Release mode")

endif ()
```
### 3.Compile PSCI-SUM
Change value of `PCSI_S UM_DEP` in the line 3 of `makefile` to your own settings, then run `make`. 