#pragma once

#include <vector>

#include "Type.hpp"

namespace HEVEC {
class Message {
public:
  Message(u64 degree) : data_(degree, 0.0) {};

  const u64 getDegree() const { return data_.size(); }
  const double *getData() const { return data_.data(); }
  double *getData() { return data_.data(); }

  double &operator[](std::size_t idx) { return data_[idx]; };
  const double &operator[](std::size_t idx) const { return data_[idx]; };

private:
  std::vector<double> data_;
};
} // namespace HEVEC