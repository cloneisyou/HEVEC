#pragma once

#include <vector>

#include "Const.hpp"
#include "Polynomial.hpp"

namespace HEVEC {
class MLWESwitchingKey {
public:
  MLWESwitchingKey(u64 rank) : rank_(rank), stack_(DEGREE / rank) {
    for (u64 i = 0; i < 2 * stack_; ++i) {
      polys_.emplace_back(rank_, MOD_Q);
      polys_.emplace_back(rank_, MOD_P);
    }
  };

  Polynomial &getPolyAModQ(u64 idx) { return polys_[idx * 4]; }
  Polynomial &getPolyAModP(u64 idx) { return polys_[idx * 4 + 1]; }
  Polynomial &getPolyBModQ(u64 idx) { return polys_[idx * 4 + 2]; }
  Polynomial &getPolyBModP(u64 idx) { return polys_[idx * 4 + 3]; }
  const Polynomial &getPolyAModQ(u64 idx) const { return polys_[idx * 4]; }
  const Polynomial &getPolyAModP(u64 idx) const { return polys_[idx * 4 + 1]; }
  const Polynomial &getPolyBModQ(u64 idx) const { return polys_[idx * 4 + 2]; }
  const Polynomial &getPolyBModP(u64 idx) const { return polys_[idx * 4 + 3]; }

  u64 getRank() const { return rank_; }
  u64 getStack() const { return stack_; }
  u64 getDegree() const { return DEGREE; }

private:
  const u64 rank_;
  const u64 stack_;
  std::vector<Polynomial> polys_;
};
} // namespace HEVEC