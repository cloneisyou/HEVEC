#pragma once

#include <vector>

#include "Ciphertext.hpp"
#include "HEval.hpp"
#include "Keys.hpp"
#include "MLWECiphertext.hpp"
#include "Message.hpp"
#include "Polynomial.hpp"
#include "SecretKey.hpp"
#include "SwitchingKey.hpp"
#include "TopK.hpp"

namespace HEVEC {

class Client {
public:
  Client(u64 log_rank);

  void genSecKey(SecretKey &res);
  void genRelinKey(SwitchingKey &res, const SecretKey &secKey);
  void genInvAutKeys(std::vector<SwitchingKey> &res, const SecretKey &secKey,
                     u64 rank);
  void genModPackKeys(std::vector<SwitchingKey> &res, const SecretKey &secKey);
  void genAutedModPackKeys(AutedModPackKeys &res, const SecretKey &secKey);
  void genInvAutedModPackKeys(AutedModPackMLWEKeys &res,
                              const SecretKey &secKey);

  void encode(Polynomial &res, const Message &msg, double scale);
  void decode(Message &res, const Polynomial &ptxt, double scale);
  void encrypt(Ciphertext &res, const Polynomial &ptxt,
               const SecretKey &secKey);
  void encrypt(Ciphertext &res, const Message &msg, const SecretKey &secKey,
               double scale);
  void encrypt(MLWECiphertext &res, const Polynomial &ptxt,
               const SecretKey &secKey);
  void encrypt(MLWECiphertext &res, const Message &msg, const SecretKey &secKey,
               double scale);
  void decrypt(Message &res, const Ciphertext &ctxt, const SecretKey &secKey,
               double scale);

  void encryptQuery(MLWECiphertext &res, const Message &msg,
                    const SecretKey &secKey, double scale);
  void encodeQuery(Polynomial &res, const Message &msg, double scale);
  void encryptKey(MLWECiphertext &res, const Message &msg,
                  const SecretKey &secKey, double scale);
  void encodeKey(Polynomial &res, const Message &msg, double scale);
  void decryptScore(std::vector<Message> &msg, std::vector<Ciphertext> &score,
                    const SecretKey &secKey, double scale);
  void topKScore(TopK &res, const std::vector<Message> &msg);

  void encryptPIR(Ciphertext &res, u64 idx, const SecretKey &secKey,
                  double scale);

  void encodePIRPayload(Polynomial &res, const unsigned char *payload);
  void decodePIRPayload(unsigned char *payload, const Message &dmsg);

  u64 getRank() const { return eval_.getRank(); }
  u64 getInvRank() const { return invRank_; }

private:
  void genSwtKey(SwitchingKey &res, const SecretKey &secKey,
                 const Polynomial &modifiedKey);

  const u64 invRank_;

  HEval eval_;
};

} // namespace HEVEC