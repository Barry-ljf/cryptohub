#include "distributed_sm2_verifier.h"

#include <glog/logging.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
namespace primihub::crypto {

// main question :resource free should be palced in the end
DistributedSM2Verification::DistributedSM2Verification(
    DistributedSM2Signature& party)
    : verify_Party_(party) {
  // transfer some value about r_,s_,ZA_,M_,
  ec_key_ = EC_KEY_new_by_curve_name(NID_sm2);
  group_ = EC_KEY_get0_group(ec_key_);
  order_ = EC_GROUP_get0_order(group_);
  generator_ = EC_GROUP_get0_generator(group_);
}

int DistributedSM2Verification::get_verification_result(
    std::pair<std::string, std::string> result, const std::string& msg) {
  verify_r_ = BN_new();
  verify_S_ = BN_new();
  BIGNUM* one = BN_new();
  BN_set_word(one, 1);

  // debug
  LOG(INFO) << "verify_r_ value: " << result.first.c_str();
  LOG(INFO) << "verify_S_ value: " << result.second.c_str();
  // notice: bn2hex must be freed here do not need.

  BN_hex2bn(&verify_r_, result.first.c_str());
  BN_hex2bn(&verify_S_, result.second.c_str());
  if (BN_cmp(verify_r_, order_) >= 0 && BN_cmp(verify_r_, one) < 0) {
    LOG(ERROR) << "r is out of range";
    return 0;
  }
  if (BN_cmp(verify_S_, order_) >= 0 && BN_cmp(verify_S_, one) < 0) {
    LOG(ERROR) << "s is out of range";
    return 0;
  }

  std::stringstream msg_temp;
  for (char ch : msg) {
    msg_temp << std::hex
             << static_cast<unsigned int>(static_cast<unsigned char>(ch));
  }
  verify_e_ = BN_new();
  std::string M = verify_Party_.Z_A_ + msg_temp.str();
  LOG(INFO) << "verify_M value: " << M;

  // notice:here is the critical step of hash!!!!!!!!!!!!!!!!!
  std::string unicoder_m_Z_M = verify_Party_.unicoder(M);
  std::string e_str = verify_Party_.generate_hash(unicoder_m_Z_M);
  // std::string e_str = verify_Party_.generate_hash(M);
  BN_hex2bn(&verify_e_, e_str.c_str());  // HASH USING SM3
  LOG(INFO) << "verify_e_str value: " << e_str;

  t_ = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  BN_mod_add(t_, verify_r_, verify_S_, order_, ctx);
  if (t_ == 0) {
    BN_CTX_free(ctx);
    BN_clear_free(verify_e_);
    BN_clear_free(t_);
    LOG(ERROR) << "t = (r+s) = 0 ";
    return 0;
  }

  // debug
  char* t_str;
  t_str = BN_bn2hex(t_);
  LOG(INFO) << "import t_str value: " << t_str;
  OPENSSL_free(t_str);

  // calculate s*G + T * P
  EC_POINT* TEM_R_ = EC_POINT_new(group_);
  verify_R_ = BN_new();
  EC_POINT_mul(group_, TEM_R_, verify_S_, verify_Party_.PublicKey_, t_,
               ctx);  // here need PublicKey_

  // calculate verify_R_
  BIGNUM* x1 = BN_new();
  BIGNUM* y1 = BN_new();
  BIGNUM* x2 = BN_new();
  BIGNUM* y2 = BN_new();
  EC_POINT_get_affine_coordinates_GFp(group_, TEM_R_, x1, y1, nullptr);

  BN_mod_add(verify_R_, x1, verify_e_, order_, ctx);

  EC_POINT_get_affine_coordinates_GFp(group_, TEM_R_, x2, y2, nullptr);

  // notice: therr is 0 will because the wrong name of var or PublicKey_ do not
  // pass.
  // debug:
  char* bignum_str;
  char* bignum_str_1;
  bignum_str = BN_bn2hex(x2);
  bignum_str_1 = BN_bn2hex(y2);
  LOG(INFO) << "x of s * G + t * P  value: " << bignum_str;
  LOG(INFO) << "y of s * G + t * P  value: " << bignum_str_1;
  OPENSSL_free(bignum_str);
  OPENSSL_free(bignum_str_1);

  // debug
  char* verify_R_str;
  verify_R_str = BN_bn2hex(verify_R_);
  LOG(INFO) << "verify_R_ value: " << verify_R_str;
  OPENSSL_free(verify_R_str);

  // //debug
  // char* t_str;
  // t_str = BN_bn2hex(t_);
  // LOG(INFO)<< "import t_str value: "  << t_str ;
  // OPENSSL_free(t_str);

  if (!BN_cmp(verify_r_, verify_R_)) {
    LOG(ERROR) << "Distributed SM2 Signature has been verified successfully";
  } else {
    LOG(ERROR) << "Distributed SM2 Signature failed";
  }

  BN_clear_free(t_);
  BN_clear_free(x1);
  BN_clear_free(y1);
  BN_CTX_free(ctx);
  EC_POINT_free(TEM_R_);
  BN_clear_free(verify_R_);

  return 0;
}
}  // namespace primihub::crypto