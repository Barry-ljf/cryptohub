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

TEST(DistributedSM2Signature, DistributedSM2Signature) {
  srand(time(nullptr));

  uint32_t rand_len = rand() % 10000;
  std::string rand_str = gen_random(rand_len);

  DistributedSM2Pubkeygen party0("12345678");
  DistributedSM2Pubkeygen party1("12345678");

  party0.cal_P_part();
  party1.cal_P_part();

  std::string P_part_str;
  party0.export_P_part(P_part_str);
  party1.import_P_part(P_part_str);

  party1.cal_P_reconst();

  std::string PublicKey_str;
  party1.export_PublicKey(PublicKey_str);
  party0.import_PublicKey(PublicKey_str);

  DistributedSM2Signature signer_p0(party0);
  DistributedSM2Signature signer_p1(party1);
  // signer_p0.cal_Q1(rand_str);

  signer_p0.cal_Q1(rand_str);

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
  verifier_P0.get_verification_result(sign_result, rand_str);
  LOG(INFO) << "End the process of verification......";
}
}  // namespace primihub::crypto