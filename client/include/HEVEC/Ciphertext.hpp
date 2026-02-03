#pragma once

#include <vector>

#include "Const.hpp"
#include "Polynomial.hpp"

namespace HEVEC {
class Ciphertext {
public:
  Ciphertext(bool is_extended = false) {
    polys_.emplace_back(DEGREE, MOD_Q);
    polys_.emplace_back(DEGREE, MOD_Q);
    if (is_extended)
      polys_.emplace_back(DEGREE, MOD_Q);
  };

  void setIsNTT(bool isNTT) {
    for (Polynomial &p : polys_)
      p.setIsNTT(isNTT);
  }

  u64 getDegree() const { return polys_[0].getDegree(); }
  bool getIsExtended() const { return polys_.size() == 3; }
  bool getIsNTT() const { return polys_[0].getIsNTT(); }

  Polynomial &getA() { return polys_[0]; }
  Polynomial &getB() { return polys_[1]; }
  Polynomial &getC() { return polys_[2]; }

  const Polynomial &getA() const { return polys_[0]; }
  const Polynomial &getB() const { return polys_[1]; }
  const Polynomial &getC() const { return polys_[2]; }

private:
  std::vector<Polynomial> polys_;
};
} // namespace HEVEC