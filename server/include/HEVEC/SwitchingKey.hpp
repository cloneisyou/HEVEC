#pragma once

#include "Const.hpp"
#include "Polynomial.hpp"

namespace HEVEC {

class SwitchingKey {
public:
  SwitchingKey()
      : polyAModQ_(DEGREE, MOD_Q), polyAModP_(DEGREE, MOD_P),
        polyBModQ_(DEGREE, MOD_Q), polyBModP_(DEGREE, MOD_P) {};

  Polynomial &getPolyAModQ() { return polyAModQ_; }
  Polynomial &getPolyAModP() { return polyAModP_; }
  Polynomial &getPolyBModQ() { return polyBModQ_; }
  Polynomial &getPolyBModP() { return polyBModP_; }
  const Polynomial &getPolyAModQ() const { return polyAModQ_; }
  const Polynomial &getPolyAModP() const { return polyAModP_; }
  const Polynomial &getPolyBModQ() const { return polyBModQ_; }
  const Polynomial &getPolyBModP() const { return polyBModP_; }

private:
  Polynomial polyAModQ_;
  Polynomial polyAModP_;
  Polynomial polyBModQ_;
  Polynomial polyBModP_;
};
} // namespace HEVEC