#pragma once

namespace PCSI {

struct PCSIContext {
    std::string ip;
    uint16_t port;
    uint32_t role;

    uint64_t bitlen;
    uint64_t ele_num;   // number of elements
    uint64_t bins_num;  // number of bins in cuckoo hash
    uint64_t hash_num;  // number of hash functions in cuckoo hash

    uint64_t poly_size;
    uint64_t poly_bytelength;
    uint64_t mega_bins_num;

    const uint64_t max_bitlen = 61;
};

}