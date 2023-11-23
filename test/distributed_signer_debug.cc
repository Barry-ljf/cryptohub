#include <glog/logging.h>
#include <gtest/gtest.h>

#include "sm2/distributed_sm2_pubkey.h"
#include "sm2/distributed_sm2_signer.h"
#include "sm2/distributed_sm2_verifier.h"

namespace primihub::crypto {
static std::string gen_random(uint32_t len) {
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  std::string tmp_s;
  tmp_s.reserve(len);

  for (uint32_t i = 0; i < len; ++i)
    tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];

  return tmp_s;
}

int reveal_ecpoint(std::string item_party_id, DistributedSM2Pubkeygen& party,
                   EC_POINT* point) {
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  EC_POINT_get_affine_coordinates_GFp(party.group_, point, x, y, nullptr);
  char* bignum_str = BN_bn2hex(x);
  char* bignum_str_1 = BN_bn2hex(y);

  std::cout << item_party_id << " x value: " << bignum_str << "\n"
            << item_party_id << " y value: " << bignum_str_1 << std::endl;

  OPENSSL_free(bignum_str);
  OPENSSL_free(bignum_str_1);
  BN_free(x);
  BN_free(y);

  return 0;
}

// int reveal_bn(){}

TEST(DistributedSM2Signature, DistributedSM2Signature) {
  srand(time(nullptr));

  uint32_t rand_len = rand() % 100000;
  std::string rand_str = gen_random(rand_len);
  std::string std_str = "message digest";
  DistributedSM2Pubkeygen party0("1234567812345678");
  DistributedSM2Pubkeygen party1("1234567812345678");

  // set d0 = 1; d1 = (d+1)^(-1)
  party0.debug_d0();
  party1.debug_d1();

  party0.cal_P_part();
  party1.cal_P_part();

  // //debug (place D_ to public in class DistributedSM2Pubkeygen to reveal)
  // char* bignum_str;
  // char* bignum_str_1;

  // bignum_str = BN_bn2hex(party0.D_);
  // bignum_str_1 = BN_bn2hex(party1.D_);

  // std::cout << "P0 private key value: " << bignum_str << std::endl;
  // std::cout << "P1 private key value: " << bignum_str_1 << std::endl;

  // OPENSSL_free(bignum_str);
  // OPENSSL_free(bignum_str_1);

  std::string P_part_str;
  party0.export_P_part(P_part_str);
  party1.import_P_part(P_part_str);

  // reveal P0_P_PART
  reveal_ecpoint("p_PART_0", party0, party0.P_part_);

  // reveal P1_P_PART
  reveal_ecpoint("p_PART_1", party1, party1.P_part_);

  party1.cal_P_reconst();

  std::string PublicKey_str;
  party1.export_PublicKey(PublicKey_str);
  party0.import_PublicKey(PublicKey_str);

  reveal_ecpoint("p_PublicKey_0", party0, party0.PublicKey_);

  DistributedSM2Signature signer_p0(party0);
  DistributedSM2Signature signer_p1(party1);
  // signer_p0.cal_Q1(rand_str);

  signer_p0.cal_Q1(std_str);

  std::string e_and_q1;
  signer_p0.export_e_Q1(e_and_q1);

  signer_p1.import_e_Q1(e_and_q1);
  signer_p1.cal_S2();
  std::string r_s2_s3;
  signer_p1.export_r_S2_S3(r_s2_s3);

  signer_p0.import_r_S2_S3(r_s2_s3);

  std::string r, s;
  signer_p0.get_signature_result(r, s);

  DistributedSM2Verification verifier_P0(signer_p0);

  LOG(INFO) << "Signature result is " << r << ", " << s << ".";

  auto sign_result = std::make_pair(r, s);

  LOG(INFO) << "Begin the process of verification......";
  verifier_P0.get_verification_result(sign_result, std_str);
  LOG(INFO) << "End the process of verification......";
}
}  // namespace primihub::crypto