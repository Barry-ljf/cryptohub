#include <thread>
#include <stdlib.h>
#include <time.h>
#include <unordered_set>

#include "common/pcsi_sum.h"
#include "common/pcsi_context.h"
#include "common/constants.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"

std::vector<uint64_t> random_ele_generator(const uint32_t n, const uint32_t bitlen, const uint32_t seed) {
    std::vector<uint64_t> eles;
    eles.reserve(n);

    // initial prng
    std::mt19937 engine(seed);
    while (eles.size() != n) {
        // select element uniformly
        std::uniform_int_distribution<uint64_t> dis(0, (1ull << bitlen) - 1);
        while (eles.size() != n) {
            eles.push_back(dis(engine));
        }

        // using unordered_set to distinct
        std::unordered_set<uint64_t> tmp;
        for (auto ele : eles) {
            tmp.insert(ele);
        }
        eles.assign(tmp.begin(), tmp.end());
    }
    std::sort(eles.begin(), eles.end());
    // process cuckoo hashing
    for (auto &ele : eles) {
        ele = ENCRYPTO::HashingTable::ElementToHash(ele) & PCSI::_61_mask;
    }
    return eles;
}

auto CreateContext(e_role role, uint64_t neles, uint64_t polynomialsize, uint64_t nmegabins) {
    return PCSI::PCSIContext{"127.0.0.1",
                              7777,  // port
                              role,
                              61,  // bitlength
                              neles,
                              static_cast<uint64_t>(neles * 1.27f),
                              3,  // # hash functions
                              polynomialsize,
                              polynomialsize * sizeof(uint64_t),
                              nmegabins
                              };
}


void PsiAnalyticsSumTest(std::size_t elem_bitlen, uint64_t neles, uint64_t polynomialsize, uint64_t nmegabins) {
  
    auto client_context = CreateContext(CLIENT, neles, polynomialsize, nmegabins);
    auto server_context = CreateContext(SERVER, neles, polynomialsize, nmegabins);

    auto client_inputs = random_ele_generator(client_context.ele_num, 61, 1);
    auto server_inputs = random_ele_generator(server_context.ele_num, 61, 2);
    for (int i=0; i < neles/3; ++i)
      client_inputs[i] = server_inputs[i];

    int c = 2;
    std::vector<uint64_t> ass_data(neles, c);

    std::uint64_t psi_client, psi_server;

    {
        auto psi_client = PCSI::exec(client_inputs, client_context, ass_data);
        std::cout << "psi client end.  " << psi_client << std::endl;
    }

}


int main(int argc, char **argv) {
//   std::cout << "1" << std::endl;
  PsiAnalyticsSumTest(61, 1ull << 12, 975, 16);
}
