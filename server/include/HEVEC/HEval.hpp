#pragma once

#include <map>

#include "hexl/ntt/ntt.hpp"

#include "Ciphertext.hpp"
#include "MLWECiphertext.hpp"
#include "MLWESwitchingKey.hpp"
#include "Polynomial.hpp"
#include "SwitchingKey.hpp"

namespace HEVEC {

class HEval {
public:
  HEval(u64 logRank);

  u64 getInv(u64 op, u64 mod);
  u64 getBitRev(u64 op, u64 mod);

  void add(Polynomial &res, const Polynomial &op1, const Polynomial &op2);
  void sub(Polynomial &res, const Polynomial &op1, const Polynomial &op2);
  void mult(Polynomial &res, const Polynomial &op1, const Polynomial &op2);
  void mult(Polynomial &res, const Polynomial &op1, u64 op2);
  void mad(Polynomial &res, const Polynomial &op1, u64 op2,
           const Polynomial &op3);
  void shift(Polynomial &res, const Polynomial &op, u64 exponent, u64 rank);
  void aut(Polynomial &res, const Polynomial &op, u64 exponent, u64 rank);
  void normMod(Polynomial &res, const Polynomial &op);
  void extract(Polynomial &res, const Polynomial &op);
  void ntt(Polynomial &res, const Polynomial &op, u64 inputModFactor = 4,
           u64 outputModFactor = 1);
  void intt(Polynomial &res, const Polynomial &op, u64 inputModFactor = 4,
            u64 outputModFactor = 1);

  void add(MLWECiphertext &res, const MLWECiphertext &op1,
           const MLWECiphertext &op2);
  void sub(MLWECiphertext &res, const MLWECiphertext &op1,
           const MLWECiphertext &op2);
  void mult(MLWECiphertext &res, const MLWECiphertext &op1, u64 op2);
  void shift(MLWECiphertext &res, const MLWECiphertext &op, u64 exponent);
  void aut(MLWECiphertext &res, const MLWECiphertext &op, u64 exponent);
  void aut(Ciphertext &res, const MLWECiphertext &op,
           const std::vector<MLWESwitchingKey> &autedModPackKeys, u64 exponent);

  void add(Ciphertext &res, const Ciphertext &op1, const Ciphertext &op2);
  void sub(Ciphertext &res, const Ciphertext &op1, const Ciphertext &op2);
  void mult(Ciphertext &res, const Ciphertext &op1, const Ciphertext &op2);
  void mult(Ciphertext &res, const Ciphertext &op1, const Polynomial &op2);
  void mult(Ciphertext &res, const Ciphertext &op1, u64 op2);
  void shift(Ciphertext &res, const Ciphertext &op, u64 exponent);
  void aut(Ciphertext &res, const Ciphertext &op, const SwitchingKey &autKey,
           u64 exponent);

  void relin(Ciphertext &res, const Ciphertext &op,
             const SwitchingKey &relinKey);
  void modPack(Ciphertext &res, const std::vector<MLWECiphertext> &op,
               const std::vector<SwitchingKey> &modPackKeys);
  void modPack(Polynomial &res, const std::vector<Polynomial> &op);
  void ntt(Ciphertext &res, const Ciphertext &op, u64 inputModFactor = 4,
           u64 outputModFactor = 1);
  void intt(Ciphertext &res, const Ciphertext &op, u64 inputModFactor = 4,
            u64 outputModFactor = 1);

  void multithreadMultSum(Ciphertext &res, const std::vector<Ciphertext> &op1,
                          const std::vector<Ciphertext> &op2);
  void multithreadMultSum(Ciphertext &res, const std::vector<Ciphertext> &op1,
                          const std::vector<Polynomial> &op2);

  void bitRevedMultithreadMultSum(Ciphertext &res,
                                  const std::vector<Ciphertext> &op1,
                                  const std::vector<Ciphertext> &op2);

  u64 getRank() const;

private:
  void keySwitch(Ciphertext &res, const Ciphertext &op,
                 const SwitchingKey &swtKey);

  const u64 logRank_;
  const u64 rank_;
  std::map<u64, intel::hexl::NTT> ntts_;
  std::map<u64, std::vector<u64>> inv_;
  std::map<u64, std::vector<u64>> bitRev_;
  std::map<u64, u64> barr_;
};

} // namespace HEVEC