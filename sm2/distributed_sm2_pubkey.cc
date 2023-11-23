#include "distributed_sm2_pubkey.h"

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

#include "proto/distributed_signature.pb.h"

using DistributedSignature::SM2_P_part_msg;
using DistributedSignature::SM2_PublicKey_msg;
namespace primihub::crypto {

DistributedSM2Pubkeygen::DistributedSM2Pubkeygen(std::string ID) : m_ID(ID) {
  ec_key_ = EC_KEY_new_by_curve_name(NID_sm2);
  group_ = EC_KEY_get0_group(ec_key_);
  order_ = EC_GROUP_get0_order(group_);
  generator_ = EC_GROUP_get0_generator(group_);
  D_ = nullptr;
}

int DistributedSM2Pubkeygen::cal_P_part(void) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *D_reverse_ = BN_new();

  if (D_ == nullptr) {
    D_ = BN_new();
    BN_rand_range(D_, order_);  // PRIVATE KEY
  }

  P_part_ = EC_POINT_new(group_);

  // here there should be a D in class DistributedSM2Signature but not D1 and
  // D2.
  D_reverse_ = BN_mod_inverse(nullptr, D_, order_, ctx);

  // calculate P1 usually
  EC_POINT_mul(group_, P_part_, nullptr, generator_, D_reverse_, ctx);

  BN_clear_free(D_reverse_);
  BN_CTX_free(ctx);

  return 0;
}

int DistributedSM2Pubkeygen::export_P_part(std::string &dest_str) {
  char *P0_str =
      EC_POINT_point2hex(group_, P_part_, POINT_CONVERSION_COMPRESSED, nullptr);

  SM2_P_part_msg msg;
  msg.set_str_p_part(std::string(P0_str));

  free(P0_str);
  P0_str = nullptr;

  if (!msg.SerializeToString(&dest_str)) {
    LOG(ERROR) << "Serialize proto msg that contain P_part failed.";
    return -1;
  }

  return 0;
}

int DistributedSM2Pubkeygen::import_P_part(const std::string &dest_str) {
  SM2_P_part_msg msg;
  if (!msg.ParseFromString(dest_str)) {
    LOG(ERROR) << "Parse from string that contain P_part failed.";
    return -1;
  }

  const std::string &P0_str = msg.str_p_part();
  P_part_ = EC_POINT_new(group_);
  if (!EC_POINT_hex2point(group_, reinterpret_cast<const char *>(P0_str.data()),
                          P_part_, nullptr)) {
    LOG(ERROR) << "Convert hex string to ec_point failed.";
    return -1;
  }

  return 0;
  // reiceive as P_part
}

int DistributedSM2Pubkeygen::cal_P_reconst(void) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *D_reverse_ = BN_new();

  EC_POINT *neg_G = EC_POINT_dup(generator_, group_);
  EC_POINT *D2_inv_P0 = EC_POINT_new(group_);
  PublicKey_ = EC_POINT_new(group_);

  // calculate D2^(-1) literally
  D_reverse_ = BN_mod_inverse(nullptr, D_, order_, ctx);

  // calculate D2^(-1)*P0_part
  EC_POINT_mul(group_, D2_inv_P0, nullptr, P_part_, D_reverse_, ctx);

  // calculate D2^(-1)*P0_part - G.
  EC_POINT_invert(group_, neg_G, ctx);
  EC_POINT_add(group_, PublicKey_, D2_inv_P0, neg_G, ctx);

  EC_POINT_free(neg_G);
  BN_clear_free(D_reverse_);
  BN_CTX_free(ctx);
  return 0;
}

int DistributedSM2Pubkeygen::export_PublicKey(std::string &dest_str) {
  char *P_str = EC_POINT_point2hex(group_, PublicKey_,
                                   POINT_CONVERSION_COMPRESSED, nullptr);

  SM2_PublicKey_msg msg;
  msg.set_str_publickey(std::string(P_str));

  free(P_str);
  P_str = nullptr;

  if (!msg.SerializeToString(&dest_str)) {
    LOG(ERROR) << "Serialize proto msg that contain PublicKey failed.";
    return -1;
  }

  return 0;
}

int DistributedSM2Pubkeygen::import_PublicKey(const std::string &dest_str) {
  SM2_PublicKey_msg msg;
  if (!msg.ParseFromString(dest_str)) {
    LOG(ERROR) << "Parse from string that contain PublicKey_ failed.";
    return -1;
  }

  const std::string &P_str = msg.str_publickey();
  PublicKey_ = EC_POINT_new(group_);
  if (!EC_POINT_hex2point(group_, reinterpret_cast<const char *>(P_str.data()),
                          PublicKey_, nullptr)) {
    LOG(ERROR) << "Convert hex string to PublicKey_ failed.";
    return -1;
  }

  return 0;
}
DistributedSM2Pubkeygen::~DistributedSM2Pubkeygen() {
  BN_clear_free(D_);  // D_
}
}  // namespace primihub::crypto