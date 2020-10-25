#pragma once

#include <cstdint>
#include <string>

struct Ip final {  // size = 4(uint32_t)
  static const int SIZE = 4;

  //
  // constructor
  //
  Ip() {}
  Ip(const uint32_t r) : ip_(r) {}
  Ip(const std::string r);
  Ip(uint8_t* r);

  //
  // casting operator
  //
  operator uint32_t() const { return ip_; }  // default
  explicit operator std::string() const;

  //
  // comparison operator
  //
  bool operator==(const Ip& r) const { return ip_ == r.ip_; }

 protected:
  uint32_t ip_;
};
