#pragma once

#include <vector>

namespace HEVEC {

class TopK {
public:
  TopK(size_t k) : result_(k) {}

  int &operator[](size_t i) { return result_[i]; }
  const int &operator[](size_t i) const { return result_[i]; }
  size_t size() const { return result_.size(); }

private:
  std::vector<int> result_;
};

} // namespace HEVEC