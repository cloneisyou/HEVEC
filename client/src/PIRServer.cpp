#include "HEVEC/PIRServer.hpp"

#ifndef HEVEC_DISABLE_OPENMP
#include <omp.h>
#endif

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/HEval.hpp"
#include "HEVEC/Polynomial.hpp"
#include "HEVEC/SwitchingKey.hpp"

namespace HEVEC {

PIRServer::PIRServer(u64 logRank, const SwitchingKey &relinKey,
                     const InvAutKeys &invAutKeys)
    : logRank_(logRank), rank_(1ULL << logRank), stack_(DEGREE >> logRank),
      eval_(logRank_), relinKey_(relinKey), invAutKeys_(invAutKeys),
      tempKeys_(rank_), tempCtxts_(rank_) {}

void PIRServer::pir(Ciphertext &res, const Ciphertext &queryFirstDim,
                    const Ciphertext &querySecondDim,
                    const std::vector<Polynomial> &db) {
  std::vector<Ciphertext> decomposedQuery(rank_), firstDim(rank_);
  decompose(decomposedQuery, queryFirstDim);
  invButterfly(decomposedQuery);
#ifndef HEVEC_DISABLE_OPENMP
#pragma omp parallel for
#endif
  for (u64 i = 0; i < rank_; ++i) {
    {
      const u64 j = 0;
      eval_.mult(firstDim[i], decomposedQuery[eval_.getBitRev(j, rank_)],
                 db[i + rank_ * j]);
    }
    for (u64 j = 1; j < rank_; ++j) {
      eval_.mult(tempCtxts_[i], decomposedQuery[eval_.getBitRev(j, rank_)],
                 db[i + rank_ * j]);
      eval_.add(firstDim[i], firstDim[i], tempCtxts_[i]);
    }
  }
  decompose(decomposedQuery, querySecondDim);
  invButterfly(decomposedQuery);
  Ciphertext temp(true);
  eval_.bitRevedMultithreadMultSum(temp, decomposedQuery, firstDim);
  eval_.relin(res, temp, relinKey_);
}

void PIRServer::decompose(std::vector<Ciphertext> &res, const Ciphertext &op) {
  const u64 step = 2 * DEGREE / rank_;

  Polynomial tempModQ(DEGREE, MOD_Q), tempModP(DEGREE, MOD_P);
  eval_.ntt(tempModQ, op.getA());
  eval_.normMod(tempModP, op.getA());
  eval_.ntt(tempModP, tempModP);
#ifndef HEVEC_DISABLE_OPENMP
#pragma omp parallel for
#endif
  for (u64 i = 0; i < rank_; ++i) {
    eval_.mult(tempKeys_[i].getPolyAModQ(), tempModQ,
               invAutKeys_.getKeys()[i].getPolyAModQ());
    eval_.mult(tempKeys_[i].getPolyBModQ(), tempModQ,
               invAutKeys_.getKeys()[i].getPolyBModQ());
    eval_.mult(tempKeys_[i].getPolyAModP(), tempModP,
               invAutKeys_.getKeys()[i].getPolyAModP());
    eval_.mult(tempKeys_[i].getPolyBModP(), tempModP,
               invAutKeys_.getKeys()[i].getPolyBModP());

    eval_.intt(tempKeys_[i].getPolyAModP(), tempKeys_[i].getPolyAModP());
    eval_.normMod(tempCtxts_[i].getA(), tempKeys_[i].getPolyAModP());
    eval_.intt(tempKeys_[i].getPolyAModQ(), tempKeys_[i].getPolyAModQ());
    eval_.sub(tempCtxts_[i].getA(), tempKeys_[i].getPolyAModQ(),
              tempCtxts_[i].getA());
    eval_.mult(tempCtxts_[i].getA(), tempCtxts_[i].getA(), INVERSE_P_MOD_Q);
    eval_.aut(res[i].getA(), tempCtxts_[i].getA(), step * i + 1, DEGREE);

    eval_.intt(tempKeys_[i].getPolyBModP(), tempKeys_[i].getPolyBModP());
    eval_.normMod(tempCtxts_[i].getA(), tempKeys_[i].getPolyBModP());
    eval_.intt(tempKeys_[i].getPolyBModQ(), tempKeys_[i].getPolyBModQ());
    eval_.sub(tempCtxts_[i].getA(), tempKeys_[i].getPolyBModQ(),
              tempCtxts_[i].getA());
    eval_.mad(tempCtxts_[i].getA(), tempCtxts_[i].getA(), INVERSE_P_MOD_Q,
              op.getB());
    eval_.aut(res[i].getB(), tempCtxts_[i].getA(), step * i + 1, DEGREE);
  }
}

void PIRServer::invButterfly(std::vector<Ciphertext> &op) {
  for (int i = logRank_ - 1; i >= 0; --i) {
    const u64 half = 1ULL << i;
    const u64 size = 2 * half;
    const u64 start = rank_ / size;
    const u64 step = DEGREE / half;
#pragma omp parallel for collapse(2)
    for (u64 j = 0; j < start; ++j) {
      for (u64 k = 0; k < half; ++k) {
        const u64 factor = start + step * k;
        const u64 idx = size * j + k;
        eval_.sub(tempCtxts_[idx], op[idx], op[idx + half]);
        eval_.add(op[idx], op[idx], op[idx + half]);
        eval_.shift(op[idx + half], tempCtxts_[idx], 2 * DEGREE - factor);
      }
    }
  }
#pragma omp parallel for
  for (u64 i = 0; i < rank_; ++i)
    eval_.ntt(op[i], op[i]);
}
} // namespace HEVEC
