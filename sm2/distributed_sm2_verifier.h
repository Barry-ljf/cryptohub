#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <iostream>

#include "distributed_sm2_signer.h"
namespace primihub::crypto {
class DistributedSM2Verification {
 public:
  DistributedSM2Signature& verify_Party_;
  EC_KEY* ec_key_;
  const BIGNUM* order_;
  const EC_GROUP* group_;
  const EC_POINT* generator_;  // must const
  EC_POINT* P_part_;
  EC_POINT* PublicKey_;

  DistributedSM2Verification(DistributedSM2Signature& party);

  // std::string generate_hash(const std::string& identifier);//compute e'=
  // H(M')

  int get_verification_result(std::pair<std::string, std::string> result,
                              const std::string& msg);  // complete Verification

  // ~DistributedSM2Verification();

 private:
  BIGNUM* verify_r_;
  BIGNUM* verify_S_;
  BIGNUM* verify_e_;
  BIGNUM* t_;
  EC_POINT* verify_point_;
  BIGNUM* verify_R_;
};
}  // namespace primihub::crypto