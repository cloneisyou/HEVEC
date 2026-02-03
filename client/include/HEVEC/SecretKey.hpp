#pragma once

#include <string>

#include "Const.hpp"
#include "Polynomial.hpp"

namespace HEVEC {
class SecretKey {
public:
  SecretKey() : polyModQ_(DEGREE, MOD_Q), polyModP_(DEGREE, MOD_P) {};

  Polynomial &getPolyQ() { return polyModQ_; }
  Polynomial &getPolyP() { return polyModP_; }
  const Polynomial &getPolyQ() const { return polyModQ_; }
  const Polynomial &getPolyP() const { return polyModP_; }

  bool save(const std::string &filepath) const;
  bool load(const std::string &filepath);

private:
  Polynomial polyModQ_;
  Polynomial polyModP_;
};
} // namespace HEVEC