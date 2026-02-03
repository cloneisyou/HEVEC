#include "HEVEC/SecretKey.hpp"

#include <fstream>
#include <iostream>

#include "HEVEC/Const.hpp"

namespace HEVEC {

bool SecretKey::save(const std::string &filepath) const {
  std::ofstream ofs(filepath, std::ios::binary);
  if (!ofs) {
    std::cerr << "Error opening file for writing: " << filepath << std::endl;
    return false;
  }
  ofs.write(reinterpret_cast<const char *>(polyModQ_.getData()),
            DEGREE * sizeof(u64));
  ofs.write(reinterpret_cast<const char *>(polyModP_.getData()),
            DEGREE * sizeof(u64));
  return ofs.good();
}

bool SecretKey::load(const std::string &filepath) {
  std::ifstream ifs(filepath, std::ios::binary);
  if (!ifs) {
    // It's not an error if the file doesn't exist, just means we need to create
    // one.
    return false;
  }
  ifs.read(reinterpret_cast<char *>(polyModQ_.getData()), DEGREE * sizeof(u64));
  ifs.read(reinterpret_cast<char *>(polyModP_.getData()), DEGREE * sizeof(u64));
  polyModQ_.setIsNTT(true);
  polyModP_.setIsNTT(true);
  return ifs.good();
}

} // namespace HEVEC 