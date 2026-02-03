#pragma once

#include <stdexcept>

class InvalidNTTStateException : public std::runtime_error {
public:
  explicit InvalidNTTStateException()
      : std::runtime_error("Invalid NTT state") {}
};

class InvalidModulusException : public std::runtime_error {
public:
  explicit InvalidModulusException() : std::runtime_error("Invalid modulus") {}
};

class InvalidExtendedStateException : public std::runtime_error {
public:
  explicit InvalidExtendedStateException()
      : std::runtime_error("Invalid extended status") {}
};

class InvalidRankException : public std::runtime_error {
public:
  explicit InvalidRankException() : std::runtime_error("Invalid stack") {}
};

class SameDataReferenceException : public std::runtime_error {
public:
  explicit SameDataReferenceException()
      : std::runtime_error("The same data is referenced by op and res") {}
};