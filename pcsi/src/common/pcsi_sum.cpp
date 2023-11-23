
#include "pcsi_sum.h"

#include "osn.h"
#include "constants.h"

#include "poly/poly.h"
#include "ot/ot.h"

#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"

#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <random>
#include <unordered_set>
#include <vector>
#include <cmath>

#include <bits/stdc++.h>

#define GREEN "\033[32m"
#define RESET "\033[0m"

namespace PCSI{

int debugx = 0;

std::unique_ptr<CSocket> create_socket(const std::string ip, uint16_t port, e_role role) {
    std::unique_ptr<CSocket> sock;
    if (role == SERVER) {
        sock = Listen(ip.c_str(), port);
    } else {
	sleep(100);
        sock = Connect(ip.c_str(), port);
    }
    return sock;
}

void interpolate_poly_with_dummy(std::vector<uint64_t>::iterator poly_offset, 
                 std::vector<uint64_t>::const_iterator x_offset, 
                 std::vector<std::vector<uint64_t>>::const_iterator y_offset,
                 std::size_t bin_num,
                 PCSIContext& ctx) {
    std::uniform_int_distribution<std::uint64_t> dist(0,
                                                    (1ull << ctx.max_bitlen) - 1);  // [0,2^61)
    std::random_device urandom("/dev/urandom");
    auto rand_func = [&urandom, &dist]() { return dist(urandom); };

    std::vector<ZpLongEle> X(ctx.poly_size), Y(ctx.poly_size), co(ctx.poly_size);
    // printf("X size = %d\n", X.size());

    for (auto i = 0ull, bin_index = 0ull; i < ctx.poly_size;) {
        if (bin_index < bin_num) {
            if ((*y_offset).size() > 0) {
                for (auto &mask : *y_offset) {
                    // X[i].ele = mask & _61_mask;
                    // printf("i = %d\n", i);

                    X.at(i).ele  = mask & _61_mask;
                    Y.at(i).ele = X[i].ele ^ *(x_offset);
                    i++;
                    // if (i > (ctx.poly_size-1)) break;
                }
            }
            x_offset++;
            y_offset++;
            bin_index++;
        } else {
            X.at(i).ele = rand_func();
            Y.at(i).ele = rand_func();
            i++;
        }
    }

    // std::ofstream xyout;
    // xyout.open("./xyout", std::ios::out | std::ios::app);
    // for (int i = 0; i < X.size(); i++) {
    //     xyout << X.at(i).ele << " " << Y.at(i).ele << std::endl;
    // }
    // xyout.close();

    Poly::interpolate(co, X, Y);

    auto coeff = co.begin();
    for (auto i = 0ull; i < co.size(); i++, poly_offset++, coeff++) {
        *poly_offset = (*coeff).ele;
    }
}

void interpolate_poly(std::vector<uint64_t>& polys, std::vector<uint64_t>& X, std::vector<std::vector<uint64_t>>& Y, PCSIContext& ctx) {
    std::size_t bins_num = Y.size();
    std::size_t Y_offset = 0;
    std::size_t bin_num_in_mega_bin = ceil_divide(bins_num, ctx.mega_bins_num);

    for (auto i = 0ull; i < ctx.mega_bins_num; i++) {
        auto poly = polys.begin() + ctx.poly_size * i;
        auto x = X.begin() + bin_num_in_mega_bin * i;
        auto y = Y.begin() + bin_num_in_mega_bin * i;

        if ((Y_offset + bin_num_in_mega_bin) > Y.size()) {
            auto overflow = (Y_offset + bin_num_in_mega_bin) % Y.size();
            bin_num_in_mega_bin -= overflow;
        }

        interpolate_poly_with_dummy(poly, x, y, bin_num_in_mega_bin, ctx);
        Y_offset += bin_num_in_mega_bin;
    }

    assert(Y_offset == Y.size());
}

void gen_corr_block(int n, int bins, int cur_level, int index, std::vector<uint64_t> &src, std::vector<std::array<osuCrypto::block,2>> &ot_output, std::vector<osuCrypto::block> &correction_blocks) {

  int levels, i, j, x, s;
  std::vector<uint64_t> bottom1;
  std::vector<uint64_t> top1;
  int values = src.size();
  uint64_t temp;

  uint64_t m0, m1, w0, w1, M0[2], M1[2], corr_mesg[2];
  osuCrypto::block corr_block, temp_block;


  if (values == 2) {
    if (n == 1) {

      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[cur_level*(bins/2)+index][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[cur_level*(bins/2)+index][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[cur_level*(bins/2)+index] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[cur_level*(bins/2)+index][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;


    }
    else {
      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[(cur_level+1)*(bins/2)+index][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(cur_level+1)*(bins/2)+index][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(cur_level+1)*(bins/2)+index] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(cur_level+1)*(bins/2)+index][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;


    }
    return; 
  }

  if (values == 3) {
      
      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[cur_level*(bins/2)+index][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[cur_level*(bins/2)+index][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[cur_level*(bins/2)+index] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[cur_level*(bins/2)+index][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;




      m0 = src[1];
      m1 = src[2];
      temp_block = ot_output[(cur_level+1)*(bins/2)+index][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(cur_level+1)*(bins/2)+index][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(cur_level+1)*(bins/2)+index] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(cur_level+1)*(bins/2)+index][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[1] = w0;
      src[2] = w1;

      
      m0 = src[0];
      m1 = src[1];
      temp_block = ot_output[(cur_level+2)*(bins/2)+index][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(cur_level+2)*(bins/2)+index][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(cur_level+2)*(bins/2)+index] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(cur_level+2)*(bins/2)+index][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[0] = w0;
      src[1] = w1;

    return;
  }
  
  levels = 2 * n - 1;
   
  for (i = 0; i < values-1; i += 2) {


      m0 = src[i];
      m1 = src[i ^ 1];
      temp_block = ot_output[(cur_level)*(bins/2)+index+i/2][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(cur_level)*(bins/2)+index+i/2][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(cur_level)*(bins/2)+index+i/2] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(cur_level)*(bins/2)+index+i/2][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[i] = w0;
      src[i ^ 1] = w1;

      bottom1.push_back(src[i]); 
      top1.push_back(src[i^1]);
    }

  if (values % 2 == 1){
    top1.push_back(src[values-1]);
  }


  gen_corr_block(n - 1, bins, cur_level + 1, index, bottom1, ot_output, correction_blocks);
  gen_corr_block(n - 1, bins, cur_level + 1, index + values / 4, top1, ot_output, correction_blocks);


  for (i = 0; i < values-1; i += 2) {


      m1 = top1[i/2];
      m0 = bottom1[i/2];
      temp_block = ot_output[(cur_level + levels - 1)*(bins/2)+index+i/2][0];
      memcpy(M0, &temp_block, sizeof(M0)); 
      w0 = M0[0] ^ m0;
      w1 = M0[1] ^ m1;
      temp_block = ot_output[(cur_level + levels - 1)*(bins/2)+index+i/2][1];
      memcpy(M1, &temp_block, sizeof(M1)); 
      corr_mesg[0] = M1[0] ^ m0 ^ w1;
      corr_mesg[1] = M1[1] ^ m1 ^ w0;
      correction_blocks[(cur_level + levels - 1)*(bins/2)+index+i/2] = osuCrypto::toBlock(corr_mesg[1], corr_mesg[0]); 
      M1[0] = m0 ^ w1;
      M1[1] = m1 ^ w0;
      ot_output[(cur_level + levels - 1)*(bins/2)+index+i/2][1] = osuCrypto::toBlock(M1[1],M1[0]);
      src[i] = w0;
      src[i ^ 1] = w1;

  }

  int idx =int(ceil(values*0.5));
  if (values % 2 == 1) {
    src[values-1] = top1[idx-1];
  }

}

std::vector<osuCrypto::block> recv_osn(std::vector<int>& dest, int bins, PCSIContext& ctx) {
    // F_osn, alice as receiver, with input Pi
    std::vector<int> src(bins);
    for (int i = 0; i < bins; i++) {
        src[i] = i;
        dest[i] = i;
    }

    osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235));

    // generate random permutation
    for (int i = bins - 1; i > 0; i--) {
        int index = prng.get<uint64_t>() % (i + 1);
        // std::cout << GREEN << index << " ";
        int tmp = dest[index];
        dest[index] = dest[i];
        dest[i] = tmp;
    } 
    // std::cout << RESET << std::endl;

    int n = int(ceil(log2(bins)));
    // generate transposition
    std::cout << "start route" << std::endl;
    route(n, 0, 0, src, dest);
    // std::cout << "finish route" << std::endl;
    // the switch set is the choices in ot
    osuCrypto::BitVector choices = retrieve_switches(bins);


    // std::cout << "finish get" << std::endl;

    // process ot
    osuCrypto::IOService ios;
    std::string name = "pcsi";
    std::vector<osuCrypto::block> recv_msg(choices.size());
    std::vector<osuCrypto::block> recv_corr(choices.size());

    rot_recv(choices, recv_msg, ctx);
    // std::ofstream rotout;
    // rotout.open("./rotout", std::ios::out);
    // for (int i = 0; i < choices.size(); i++) {
    //     uint64_t tmp[2];
    //     memcpy(tmp, &recv_msg[i], sizeof(tmp));
    //     rotout << choices[i] << " " << tmp[0] << tmp[1] << std::endl;
    // }
    // rotout.close();
    // std::cout << "finish rot" << std::endl;
    // getchar();


    osuCrypto::Session ep(ios, ctx.ip, ctx.port + 100, osuCrypto::SessionMode::Server, name);
    auto osn_recv_chl = ep.addChannel(name, name);

    osn_recv_chl.recv(recv_corr.data(), recv_corr.size()); // this statement error

    std::cout << "finish ot" << std::endl;
    // consider switch
    uint64_t tmp_msg[2], tmp_corr[2];
    for (int i = 0; i < recv_msg.size(); i++) {
        // choices means switches
        if (choices[i]) {
            memcpy(tmp_corr, &recv_corr[i], sizeof(tmp_corr)); 
            memcpy(tmp_msg, &recv_msg[i], sizeof(tmp_msg));
            tmp_msg[0] = tmp_corr[0] ^ tmp_msg[0];
            tmp_msg[1] = tmp_corr[1] ^ tmp_msg[1];
            recv_msg[i] = osuCrypto::toBlock(tmp_msg[1], tmp_msg[0]);
        }
    }

    return recv_msg;
}

// SELECT SUM(A.VAL) FROM A UNION B
// SUM(A.VAL) + SUM(B.VAL) - SUM(A intersection B.VAL)

std::vector<std::vector<uint64_t>> send_osn(int bins, PCSIContext& ctx) {
    int n = int(ceil(log2(bins)));   // bins = 10, n = 4
    int levels = 2 * n - 1;   // 7
    int switch_num = levels * (bins / 2); // 7*5 = 35
    std::vector<uint64_t> masks(bins);
    std::vector<std::vector<uint64_t>> mat_masks(bins);


    osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235));

    for (int i = 0; i < bins; i++) {
        uint64_t r = prng.get<uint64_t>();
        masks[i] = r;
        mat_masks[i].push_back(r);  // think;
    }

    std::vector<std::array<osuCrypto::block, 2>> ot_msg(switch_num);  // 电路中输入、输出、门的个数
    // ot_msg is valued in rot, it is outPut;
    rot_send(ot_msg, ctx);    // this is OT , ot_msg is output;

    std::vector<osuCrypto::block> corr_blocks(switch_num);

    gen_corr_block((unsigned int)n, bins, 0, 0, masks, ot_msg, corr_blocks);

    osuCrypto::IOService ios;
    std::string name = "pcsi";

    osuCrypto::Session ep(ios, ctx.ip, ctx.port + 100, osuCrypto::SessionMode::Client, name); 
    auto osn_send_chl = ep.addChannel(name, name);
    // osn_send_chl.asyncSend(corr_blocks);
    osn_send_chl.send(corr_blocks);

    for (int i = 0; i < bins; i++) {
        mat_masks[i].push_back(masks[i]);
    }
    return mat_masks;
}

std::vector<uint64_t> client_opprf(const std::vector<uint64_t>& eles, std::vector<uint64_t>& cuckoo_table, PCSIContext& ctx) {
    // 1. cuckoo hashing
    // initial cuckoo table
    ENCRYPTO::CuckooTable table(static_cast<size_t>(ctx.bins_num));
    table.SetNumOfHashFunctions(ctx.hash_num);
    table.Insert(eles);
    // map elements
    table.MapElements();
    // table.Print();
    // get vector
    cuckoo_table = table.AsRawVector();
    // std::cout << "test, finish get vector ." << std::endl;

    std::cout << "[pcsi] finish cuckoo" << std::endl;
    // getchar();

    // 2. oprf
    std::vector<uint64_t> masks = oprf_receiver(cuckoo_table, ctx);

    // std::ofstream oprfout;
    // oprfout.open("./fout", std::ios::out);
    // for (int i = 0; i < masks.size(); i++) {
    //     oprfout << masks[i] << std::endl;
    // }
    // oprfout.close();
    std::cout << "[client]finish oprf" << std::endl;
    std::cout << "[client]ctx.ip" <<ctx.ip<< std::endl;
    std::cout << "[client]ctx.port" <<ctx.port<< std::endl;
    // 3. get polynominal and evaluate
    std::cout << "[client]ctx.role" << ctx.role<<std::endl;


    std::string pcsi_csocket_name = "pcsi_csocket";
    osuCrypto::IOService ios;
    osuCrypto::Session ep(ios, ctx.ip, ctx.port + 300, osuCrypto::SessionMode::Client, pcsi_csocket_name);
    auto client_chl = ep.addChannel(pcsi_csocket_name, pcsi_csocket_name);
    //std::unique_ptr<CSocket> sock = create_socket(ctx.ip, ctx.port, static_cast<e_role>(ctx.role));

    const auto bin_num_in_mega_bin = ceil_divide(ctx.bins_num, ctx.mega_bins_num);
    std::vector<std::vector<ZpLongEle>> polys(ctx.mega_bins_num);
    std::vector<ZpLongEle> X(ctx.bins_num), Y(ctx.bins_num);
    for (auto &poly : polys) {
        poly.resize(ctx.poly_size);
    }

    for (auto i = 0ull; i < X.size(); i++) {
        X.at(i).ele = masks.at(i);
    }
    // 3.1 receive poly from server
    std::vector<uint8_t> poly_buffer(ctx.mega_bins_num * ctx.poly_bytelength, 0);
    client_chl.recv(poly_buffer.data(),ctx.mega_bins_num * ctx.poly_bytelength);
    //sock->Receive(poly_buffer.data(), ctx.mega_bins_num * ctx.poly_bytelength);
    //sock->Close();

    // 3.2 evaluate
    for (auto i = 0ull; i < poly_buffer.size() && i < ctx.mega_bins_num; i++) {  // cyc:check
        for (auto j = 0ull; j < ctx.poly_size; j++) {
            // polys[i][j].ele = (reinterpret_cast<uint64_t *>(
            polys.at(i).at(j).ele = (reinterpret_cast<uint64_t *>(poly_buffer.data()))[i * ctx.poly_size + j];
        }
    }

    // std::ofstream yout;
    // yout.open("./yout", std::ios::out);

    for (auto i = 0; i < X.size(); i++) {
        auto p = i / bin_num_in_mega_bin;
        // ZpLongEle tmp(i);
        Poly::eval(Y.at(i), polys.at(p), X.at(i));
        // yout << X.at(i).ele << " " << Y.at(i).ele << std::endl;
    }
    // yout.close();

    // 3.3 xor
    std::vector<uint64_t> result;
    result.reserve(X.size());
    for (auto i = 0ull; i < X.size(); i++) {
        result.push_back(X[i].ele ^ Y[i].ele);
    }

    return result;
}

std::vector<uint64_t> server_opprf(const std::vector<uint64_t>& eles, PCSIContext& ctx) {

    ENCRYPTO::SimpleTable table(static_cast<size_t>(ctx.bins_num));
    table.SetNumOfHashFunctions(ctx.hash_num);
    table.Insert(eles);
    table.MapElements();
    // table.Print();
    // getchar();

    auto simple_table = table.AsRaw2DVector();
    auto masks = oprf_sender(simple_table, ctx);

    // std::ofstream oprfout;
    // oprfout.open("./prfout", std::ios::out);
    // for (int i = 0; i < masks.size(); i++) {
    //     for (int j = 0; j < masks[i].size(); j++) {
    //         oprfout << masks[i][j] << " ";
    //     }
    //     oprfout << std::endl;
    // }
    // oprfout.close();
    std::cout << "[server]finish oprf" << std::endl;

    std::vector<uint64_t> polys(ctx.mega_bins_num * ctx.poly_size, 0);
    std::vector<uint64_t> X(ctx.bins_num);

    std::random_device urandom("/dev/urandom");
    std::uniform_int_distribution<uint64_t> dist(1, (1ull << ctx.max_bitlen) - 1);
    std::generate(X.begin(), X.end(), [&]() { return dist(urandom); });
    auto tmp = X;
    std::sort(tmp.begin(), tmp.end());
    auto last = std::unique(tmp.begin(), tmp.end());
    tmp.erase(last, tmp.end());
    assert(tmp.size() == X.size());

    // std::ofstream sout;
    // sout.open("./sout", std::ios::out);
    // for (int i = 0; i < X.size(); i++) {
    //     sout << X[i] << std::endl;
    // }
    // sout.close();
    std::cout << "sfinsih" << std::endl;
    // getchar();

    // std::cout << X[0] << std::endl;
    // getchar();

    // for (int i = 0; i < X.size(); i++) {
    //     X.at(i) = i;
    // }

    // for (int i = 0; i < masks.size(); i++) {
    //     for (int j = 0; j < masks[i].size(); j++) {
    //         masks.at(i).at(j) = i + j;
    //     }
    // }

    interpolate_poly(polys, X, masks, ctx);   // test is correctness.

    // std::ofstream polyout;
    // polyout.open("./polyout", std::ios::out);
    // for (int i = 0; i < polys.size(); i++) {
    //     polyout << polys.at(i) << std::endl;
    // }
    // polyout.close();
    std::cout << "[server] start csocket" << std::endl; 
    std::cout << "[server] ctx.ip" <<ctx.ip <<std::endl;
    std::cout << "[server] ctx.port" << ctx.port<<std::endl;
    std::cout << "[server] role: " << ctx.role<<std::endl;
    //std::unique_ptr<CSocket> sock = create_socket(ctx.ip, ctx.port, static_cast<e_role>(ctx.role));

    std::string pcsi_csocket_name = "pcsi_csocket";
    osuCrypto::IOService ios;
    osuCrypto::Session ep(ios, ctx.ip, ctx.port + 300, osuCrypto::SessionMode::Server, pcsi_csocket_name);
    auto server_chl = ep.addChannel(pcsi_csocket_name, pcsi_csocket_name);


    server_chl.asyncSend((uint8_t *)polys.data(), ctx.mega_bins_num * ctx.poly_bytelength);
    //sock->Send((uint8_t *)polys.data(), ctx.mega_bins_num * ctx.poly_bytelength); // 已测试，不是sock的问题
    //sock->Close();

    std::cout << "socket has setup" << std::endl;

    return X;
}

uint64_t exec(const std::vector<uint64_t>& inputs, PCSIContext& ctx, const std::vector<uint64_t>& data) {
    // network
    std::cout << "ctx.role:" <<ctx.role << std::endl;
    std::cout << "CLIENT:" <<CLIENT<< std::endl;
    std::cout << "SERVER:" <<SERVER<< std::endl;
    // std::unique_ptr<CSocket> sock = create_socket(ctx.ip, ctx.port, static_cast<e_role>(ctx.role));
    // sock->Close();
    std::cout << "6"<< std::endl;
    std::vector<uint64_t> input_bak(inputs), sets;
    int bins = ctx.bins_num;   // coocku hash bins num: hash值的长度？ = n_eles * 1.27；与元素个数线性关系
    uint64_t output = 0;
    //std::cout << "ctx.role:" <<ctx.role << std::endl;
    if (ctx.role == CLIENT) {
        // client give Data
        // 1. osn preprocessing 
        // 1.1 initial paramters
        std::vector<int> dest(bins);
        int n = int(ceil(log2(bins)));
        int levels = 2 * n - 1;
        initialize(bins, levels);
	    std::cout << "[client]finish 1.1" << std::endl;
        // 1.2 processing offline osn
        std::vector<osuCrypto::block> ot_output;
        ot_output = recv_osn(dest, bins, ctx); // ****suppose it is correct
        // std::ofstream permout;
        // permout.open("./permout", std::ios::out);
        // for (int i = 0; i < dest.size(); i++) {
        //     permout << dest[i] << std::endl;
        // }
        // permout.close();
        // dest : x_Pi(w) ^ Mask, is output;
	    std::cout << "[client]finish 1" << std::endl;
        // 2. pcsi preprocessing 
        std::vector<uint64_t> cuckoo_table;
        sets = client_opprf(input_bak, cuckoo_table, ctx);
	    std::cout << "[client]finish 2" << std::endl;








        // 3. online osn
        std::vector<uint64_t> shuffled_sets(bins);
        for (int i = 0; i < bins; i++) {
            shuffled_sets[i] = sets[dest[i]];
        }

        // std::ofstream tout;
        // tout.open("./tout", std::ios::out);
        // for (int i = 0; i < sets.size(); i++) {
        //     tout << sets[i] << std::endl;
        // }
        // tout.close();

        std::string name = "pcsi";
        osuCrypto::IOService ios;
        osuCrypto::Session ep(ios, ctx.ip, ctx.port + 20, osuCrypto::SessionMode::Server, name);
        auto recv_chl = ep.addChannel(name, name);
        std::vector<uint64_t> input_vec(bins);
        recv_chl.recv(input_vec.data(), input_vec.size());

        std::vector<std::vector<osuCrypto::block>> mat_ot_output(levels, std::vector<osuCrypto::block>(bins));
        int index = 0;
        for (int i = 0; i < levels; i++) {
            for (int j = 0; j < bins / 2; j++) {
                mat_ot_output[i][j] = ot_output[index++];
            }
        }
        masked_eval(n, 0, 0, input_vec, mat_ot_output);

        // std::ofstream aout;
        // aout.open("./aout", std::ios::out);
        // for (int i = 0; i < input_vec.size(); i++) {
        //     aout << input_vec[i] << std::endl;
        // }
        // aout.close();

	    std::cout << "[client]finish 3" << std::endl;






        // 4. send the result to process equality test
        std::string name_ = "pcsi";
        osuCrypto::Session ep_(ios, ctx.ip, ctx.port + 30, osuCrypto::SessionMode::Server, name_);
        auto send_chl_eq = ep_.addChannel(name_, name_);
        std::vector<uint64_t> sets_eq;
        for (int i = 0; i < bins; i++) {
            sets_eq.push_back(shuffled_sets[i] ^ input_vec[i]);
        }

        // std::ofstream axout;
        // axout.open("./axout", std::ios::out);
        // for (int i = 0; i < sets_eq.size(); i++) {
        //     axout << sets_eq[i] << std::endl;
        // }
        // axout.close();

        send_chl_eq.asyncSend(sets_eq);
	    std::cout << "[client]finish 4" << std::endl;






        // 5. do sum
        std::vector<std::pair<uint64_t, uint64_t>> candidate;
        candidate.reserve(input_bak.size());
        std::transform(input_bak.begin(), input_bak.end(), data.begin(), std::back_inserter(candidate), [](uint64_t x, uint64_t y){ return std::make_pair(x, y); });
        std::sort(candidate.begin(), candidate.end());

        std::vector<uint64_t> candidate_index(candidate.size());
        for (int i = 0; i < candidate.size(); i++) {
            candidate_index[i] = candidate[i].first;
        }

        // assign 
        for (int i = 0; i < cuckoo_table.size(); i++) {
            std::vector<uint64_t>::iterator it = std::lower_bound(candidate_index.begin(), candidate_index.end(), cuckoo_table[i]);

            if (it == std::end(candidate_index)) {
                cuckoo_table[i] = 0;
            } else {
                cuckoo_table[i] = candidate[it-candidate_index.begin()].second;
            }
        }

        std::vector<uint64_t> shuffled_table(cuckoo_table.size());
        for (int i = 0; i < cuckoo_table.size(); i++) {
            shuffled_table[i] = cuckoo_table[dest[i]];
        }

        osuCrypto::PRNG prng(_mm_set_epi32(0, 0, 0, 0));
        std::vector<std::vector<osuCrypto::block>> msg(cuckoo_table.size());

        for (int i = 0; i < cuckoo_table.size(); i++) {
            int r = prng.get<uint64_t>();
            msg[i].push_back(osuCrypto::toBlock(0, 0 - r));
            msg[i].push_back(osuCrypto::toBlock(0, shuffled_table[i] - r));
            output += r;
        }
        ot_send(msg, ctx);

    } 
    
    
    
    
    
    
    
    
    



    
    
    
    
    
    
    
    else {
        // offline osn
        // server is receiver, have func, not data;
        std::vector<std::vector<uint64_t>> pre_masks;
        pre_masks = send_osn(bins, ctx);

        // pcsi preprocessing
        sets = server_opprf(input_bak, ctx);

        // online osn
        osuCrypto::IOService ios;
        std::string name = "pcsi";
        osuCrypto::Session ep(ios, ctx.ip, ctx.port + 20, osuCrypto::SessionMode::Client, name);
        auto send_chl = ep.addChannel(name, name);
        std::vector<uint64_t> output_masks, benes_input;

        for (int i = 0; i < sets.size(); i++) {
            pre_masks[i][0] ^= sets[i];
        }
        for (int i = 0; i < bins; i++) {
            benes_input.push_back(pre_masks[i][0]);
        }
        send_chl.asyncSend(benes_input);
        for (int i = 0; i < ctx.bins_num; i++) {
            output_masks.push_back(pre_masks[i][1]);
        }

        // std::ofstream sout;
        // sout.open("./sout", std::ios::out);
        // for (int i = 0; i < sets.size(); i++) {
        //     sout << sets[i] << std::endl;
        // }
        // sout.close();

        // std::ofstream bout;
        // bout.open("./bout", std::ios::out);
        // for (int i = 0; i < output_masks.size(); i++) {
        //     bout << output_masks[i] << std::endl;
        // }
        // bout.close();






        // equality test
        std::string name_ = "pcsi";
        osuCrypto::Session ep_(ios, ctx.ip, ctx.port + 30, osuCrypto::SessionMode::Client, name_);
        auto recv_chl_eq = ep_.addChannel(name_, name_);
        std::vector<uint64_t> sets_eq(bins);
        recv_chl_eq.recv(sets_eq.data(), sets_eq.size());

        osuCrypto::BitVector char_vec(sets_eq.size());
        for (int i=0; i < sets_eq.size();++i) {
            if (sets_eq[i] == output_masks[i]) {
                char_vec[i] = 1;
            }
        }






        // do sum
        std::vector<osuCrypto::block> recv_msg(char_vec.size());
        ot_recv(char_vec, recv_msg, ctx);
        uint64_t ot_msg[2];
        for (int i=0; i < recv_msg.size(); ++i) {
            memcpy(ot_msg, &recv_msg[i], sizeof(ot_msg)); 
            output += ot_msg[0];
        }
    }
    return output;
}

}

