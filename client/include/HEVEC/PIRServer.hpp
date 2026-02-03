#pragma once

#include "Ciphertext.hpp"
#include "HEval.hpp"
#include "Keys.hpp"
#include "Polynomial.hpp"
#include "SwitchingKey.hpp"

namespace HEVEC {

class PIRServer {
public:
  PIRServer(u64 logRank, const SwitchingKey &relinKey,
            const InvAutKeys &invAutKeys);

  void pir(Ciphertext &res, const Ciphertext &queryFristDim,
           const Ciphertext &querySecondDim, const std::vector<Polynomial> &db);

  void decompose(std::vector<Ciphertext> &res, const Ciphertext &op);
  void invButterfly(std::vector<Ciphertext> &op);

private:
  const u64 logRank_;
  const u64 rank_;
  const u64 stack_;

  HEval eval_;

  const SwitchingKey &relinKey_;
  const InvAutKeys &invAutKeys_;

  std::vector<SwitchingKey> tempKeys_;
  std::vector<Ciphertext> tempCtxts_;
};
} // namespace HEVEC