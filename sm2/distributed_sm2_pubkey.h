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

#ifndef DISTRIBUTEDSM2PUBKEYGEN_H
#define DISTRIBUTEDSM2PUBKEYGEN_H

namespace primihub::crypto {
class DistributedSM2Pubkeygen {
 public:
  friend class DistributedSM2Verification;
  friend class DistributedSM2Signature;

  std::string m_ID;
  EC_POINT* PublicKey_;
  EC_POINT* P_part_;
  EC_KEY* ec_key_;
  const BIGNUM* order_;
  const EC_GROUP* group_;
  const EC_POINT* generator_;

  DistributedSM2Pubkeygen(std::string ID);
  void debug_d0() {
    D_ = BN_new();
    BN_hex2bn(&D_, "1");
  }
  void debug_d1() {
    D_ = BN_new();
    BN_hex2bn(&D_,
              "4DFE9D9C1F5901D4E6F58E4EC3D04567822D2550F9B88E826D1B5B3AB9CD0FE"
              "0");  // NOTICE !!!(d+1)^(-1)
  }

  int cal_P_part(void);

  int export_P_part(std::string& dest_str);  // output P computed by oneself

  int import_P_part(
      const std::string& msg);  // receive P computed by another part

  int cal_P_reconst(void);  //

  int export_PublicKey(std::string& dest_str);  // output P computed by oneself

  int import_PublicKey(
      const std::string& msg);  // receive P computed by another part

  ~DistributedSM2Pubkeygen();

 private:
  BIGNUM* D_;
  BIGNUM* D_reverse_;
};
}  // namespace primihub::crypto
#endif  // DISTRIBUTED_SM2_PUBKEYGEN_H
