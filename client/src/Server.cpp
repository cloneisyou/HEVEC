#include "HEVEC/Server.hpp"

#include <cstring>

#include "HEVEC/Ciphertext.hpp"
#include "HEVEC/Const.hpp"
#include "HEVEC/HEval.hpp"
#include "HEVEC/MLWECiphertext.hpp"
#include "HEVEC/MLWESwitchingKey.hpp"
#include "HEVEC/Polynomial.hpp"
#include "HEVEC/Random.hpp"
#include "HEVEC/SwitchingKey.hpp"

namespace HEVEC {

Server::Server(u64 logRank, const SwitchingKey &relinKey,
               const AutedModPackKeys &autedModPackKeys,
               const AutedModPackMLWEKeys &autedModPackMLWEKeys)
    : logRank_(logRank), rank_(1ULL << logRank), stack_(DEGREE >> logRank),
      eval_(logRank_), relinKey_(relinKey), autedModPackKeys_(autedModPackKeys),
      autedModPackMLWEKeys_(autedModPackMLWEKeys) {}

void Server::cacheQuery(CachedQuery &res, const MLWECiphertext &query) {
  MLWESwitchingKey up(rank_);

#pragma omp parallel for
  for (u64 i = 0; i < stack_; ++i) {
    eval_.normMod(up.getPolyAModP(i), query.getA(i));
    eval_.ntt(up.getPolyAModQ(i), query.getA(i));
    eval_.ntt(up.getPolyAModP(i), up.getPolyAModP(i));
  }

#pragma omp parallel for
  for (u64 i = 0; i < rank_; ++i) {
    const u64 exponent = 2 * i + 1;
    Ciphertext &ctxt = res.getCtxts()[eval_.getBitRev(i, rank_)];

    MLWESwitchingKey multed(rank_);

    ctxt.setIsNTT(false);

    std::memset(ctxt.getB().getData(), 0, sizeof(u64) * DEGREE);

#pragma omp parallel for
    for (u64 j = 0; j < rank_; ++j)
      ctxt.getB()[j * stack_] = query.getB()[j];
#pragma omp parallel for
    for (u64 k = 0; k < stack_; ++k) {
      {
        u64 j = 0;
        eval_.mult(multed.getPolyAModQ(k), up.getPolyAModQ(j),
                   autedModPackMLWEKeys_.getKeys()[i][0].getPolyAModQ(k));
        eval_.mult(multed.getPolyBModQ(k), up.getPolyAModQ(j),
                   autedModPackMLWEKeys_.getKeys()[i][0].getPolyBModQ(k));
        eval_.mult(multed.getPolyAModP(k), up.getPolyAModP(j),
                   autedModPackMLWEKeys_.getKeys()[i][0].getPolyAModP(k));
        eval_.mult(multed.getPolyBModP(k), up.getPolyAModP(j),
                   autedModPackMLWEKeys_.getKeys()[i][0].getPolyBModP(k));
      }
      Polynomial tempQ(rank_, MOD_Q), tempP(rank_, MOD_P);
      for (u64 j = 1; j < stack_; ++j) {
        eval_.mult(tempQ, up.getPolyAModQ(j),
                   autedModPackMLWEKeys_.getKeys()[i][j].getPolyAModQ(k));
        eval_.add(multed.getPolyAModQ(k), multed.getPolyAModQ(k), tempQ);
        eval_.mult(tempQ, up.getPolyAModQ(j),
                   autedModPackMLWEKeys_.getKeys()[i][j].getPolyBModQ(k));
        eval_.add(multed.getPolyBModQ(k), multed.getPolyBModQ(k), tempQ);
        eval_.mult(tempP, up.getPolyAModP(j),
                   autedModPackMLWEKeys_.getKeys()[i][j].getPolyAModP(k));
        eval_.add(multed.getPolyAModP(k), multed.getPolyAModP(k), tempP);
        eval_.mult(tempP, up.getPolyAModP(j),
                   autedModPackMLWEKeys_.getKeys()[i][j].getPolyBModP(k));
        eval_.add(multed.getPolyBModP(k), multed.getPolyBModP(k), tempP);
      }
      eval_.intt(multed.getPolyAModP(k), multed.getPolyAModP(k));
      eval_.normMod(tempQ, multed.getPolyAModP(k));
      eval_.intt(multed.getPolyAModQ(k), multed.getPolyAModQ(k));
      eval_.sub(multed.getPolyAModQ(k), multed.getPolyAModQ(k), tempQ);
      eval_.mult(multed.getPolyAModQ(k), multed.getPolyAModQ(k),
                 INVERSE_P_MOD_Q);

      eval_.intt(multed.getPolyBModP(k), multed.getPolyBModP(k));
      eval_.normMod(tempQ, multed.getPolyBModP(k));
      eval_.intt(multed.getPolyBModQ(k), multed.getPolyBModQ(k));
      eval_.sub(multed.getPolyBModQ(k), multed.getPolyBModQ(k), tempQ);
      eval_.mult(multed.getPolyBModQ(k), multed.getPolyBModQ(k),
                 INVERSE_P_MOD_Q);
    }
#pragma omp parallel for
    for (u64 j = 0; j < multed.getRank(); ++j) {
      for (u64 k = 0; k < multed.getStack(); ++k) {
        ctxt.getA()[j * stack_ + k] = multed.getPolyAModQ(k)[j];
        ctxt.getB()[j * stack_ + k] += multed.getPolyBModQ(k)[j];
        if (ctxt.getB()[j * stack_ + k] >= MOD_Q)
          ctxt.getB()[j * stack_ + k] -= MOD_Q;
      }
    }

    Ciphertext temp;
    eval_.aut(temp.getA(), ctxt.getA(), exponent, DEGREE);
    eval_.aut(temp.getB(), ctxt.getB(), exponent, DEGREE);
    eval_.ntt(ctxt.getA(), temp.getA());
    eval_.ntt(ctxt.getB(), temp.getB());
  }
}

void Server::cacheQuery(CachedPlaintextQuery &res, const Polynomial &query) {
#pragma omp parallel for
  for (u64 i = 0; i < rank_; ++i) {
    Polynomial temp(DEGREE, MOD_Q);
    Polynomial &poly = res.getPolys()[eval_.getBitRev(i, rank_)];
    for (u64 j = 0; j < rank_; ++j)
      poly[j * stack_] = query[j];
    eval_.aut(temp, poly, 2 * i + 1, DEGREE);
    eval_.ntt(poly, temp);
  }
}

void Server::cacheKeys(CachedKeys &res,
                       const std::vector<MLWECiphertext> &keys) {
  u64 logNumber = 0;
  while ((1ULL << logNumber) < keys.size())
    ++logNumber;
  const u64 number = 1ULL << logNumber;
  const u64 block = rank_ * number / DEGREE;

  std::vector<std::vector<MLWECiphertext>> temp(block);
#pragma omp parallel for
  for (u64 i = 0; i < block; ++i) {
    temp[i].reserve(stack_);
    for (u64 j = 0; j < stack_; ++j)
      temp[i].emplace_back(rank_);
  }
  for (u64 iter = 0; iter < stack_; ++iter) {
    {
      u64 i = 0;
      const u64 half = 1ULL << i;
      const u64 size = half << 1;
      const u64 start = block / size;
      const u64 step = rank_ >> i;
#pragma omp parallel for collapse(2)
      for (u64 j = 0; j < start; ++j) {
        for (u64 k = 0; k < half; ++k) {
          const u64 factor = start + step * k;
          const u64 index = size * j + k;
          MLWECiphertext twiddle(rank_);
          eval_.shift(
              twiddle,
              keys[eval_.getBitRev(index + half, block) * stack_ + iter],
              factor);
          eval_.sub(temp[index + half][iter],
                    keys[eval_.getBitRev(index, block) * stack_ + iter],
                    twiddle);
          eval_.add(temp[index][iter],
                    keys[eval_.getBitRev(index, block) * stack_ + iter],
                    twiddle);
        }
      }
    }
    for (u64 i = 1; i < logNumber; ++i) {
      const u64 half = 1ULL << i;
      const u64 size = half << 1;
      const u64 start = block / size;
      const u64 step = rank_ >> i;
#pragma omp parallel for collapse(2)
      for (u64 j = 0; j < start; ++j) {
        for (u64 k = 0; k < half; ++k) {
          const u64 factor = start + step * k;
          const u64 index = size * j + k;
          MLWECiphertext twiddle(rank_);
          eval_.shift(twiddle, temp[index + half][iter], factor);
          eval_.sub(temp[index + half][iter], temp[index][iter], twiddle);
          eval_.add(temp[index][iter], temp[index][iter], twiddle);
        }
      }
    }
  }

  const u64 step = 2 * DEGREE / number;
#pragma omp parallel for
  for (u64 i = 0; i < block; ++i) {
    std::vector<MLWECiphertext> auted;
    auted.reserve(stack_);
    for (u64 i = 0; i < stack_; ++i)
      auted.emplace_back(rank_);
    for (u64 j = 0; j < stack_; ++j) {
      eval_.aut(auted[j], temp[eval_.getInv(step * i + 1, rank_) / step][j],
                step * i + 1);
    }
    eval_.modPack(res.getCtxts()[eval_.getBitRev(i, block)], auted,
                  autedModPackKeys_.getKeys()[i * DEGREE / number]);
  }
}

// void Server::cacheKeys(CachedPlaintextKeys &res,
//                        const std::vector<Polynomial> &keys) {
//   std::vector<std::vector<Polynomial>> temp(rank_);
// #pragma omp parallel for
//   for (u64 i = 0; i < rank_; ++i) {
//     temp[i].reserve(stack_);
//     for (u64 j = 0; j < stack_; ++j)
//       temp[i].emplace_back(rank_, MOD_Q);
//   }
//   for (u64 iter = 0; iter < stack_; ++iter) {
//     {
//       u64 i = 0;
//       const u64 half = 1ULL << i;
//       const u64 size = half << 1;
//       const u64 start = rank_ >> (i + 1);
//       const u64 step = rank_ >> i;
// #pragma omp parallel for collapse(2)
//       for (u64 j = 0; j < start; ++j) {
//         for (u64 k = 0; k < half; ++k) {
//           const u64 factor = start + step * k;
//           const u64 index = size * j + k;
//           Polynomial twiddle(rank_, MOD_Q);
//           eval_.shift(
//               twiddle,
//               keys[eval_.getBitRev(index + half, rank_) * stack_ + iter],
//               factor, rank_);
//           eval_.sub(temp[index + half][iter],
//                     keys[eval_.getBitRev(index, rank_) * stack_ + iter],
//                     twiddle);
//           eval_.add(temp[index][iter],
//                     keys[eval_.getBitRev(index, rank_) * stack_ + iter],
//                     twiddle);
//         }
//       }
//     }
//     for (u64 i = 1; i < logRank_; ++i) {
//       const u64 half = 1ULL << i;
//       const u64 size = half << 1;
//       const u64 start = rank_ >> (i + 1);
//       const u64 step = rank_ >> i;
// #pragma omp parallel for collapse(2)
//       for (u64 j = 0; j < start; ++j) {
//         for (u64 k = 0; k < half; ++k) {
//           const u64 factor = start + step * k;
//           const u64 index = size * j + k;
//           Polynomial twiddle(rank_, MOD_Q);
//           eval_.shift(twiddle, temp[index + half][iter], factor, rank_);
//           eval_.sub(temp[index + half][iter], temp[index][iter], twiddle);
//           eval_.add(temp[index][iter], temp[index][iter], twiddle);
//         }
//       }
//     }
//   }
// #pragma omp parallel for
//   for (u64 i = 0; i < rank_; ++i) {
//     std::vector<Polynomial> auted;
//     auted.reserve(stack_);
//     for (u64 i = 0; i < stack_; ++i)
//       auted.emplace_back(rank_, MOD_Q);
//     for (u64 j = 0; j < stack_; ++j) {
//       eval_.aut(auted[j], temp[eval_.getInv(2 * i + 1, rank_) / 2][j],
//                 2 * i + 1, rank_);
//     }
//     eval_.modPack(res.getPolys()[eval_.getBitRev(i, rank_)], auted);
//   }
// }

void Server::innerProduct(Ciphertext &res, const CachedQuery &cachedQuery,
                          const CachedKeys &cachedKey) {
  Ciphertext temp(true);
  eval_.multithreadMultSum(temp, cachedQuery.getCtxts(), cachedKey.getCtxts());
  eval_.mult(temp, temp, rank_);
  eval_.relin(res, temp, relinKey_);
}

void Server::innerProduct(Ciphertext &res,
                          const CachedPlaintextQuery &cachedQuery,
                          const CachedKeys &cachedKey) {
  eval_.multithreadMultSum(res, cachedKey.getCtxts(), cachedQuery.getPolys());
  eval_.mult(res, res, rank_);
}
} // namespace HEVEC