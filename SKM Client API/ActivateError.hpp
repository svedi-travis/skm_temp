#pragma once

#include <exception>

#include "ActivateError.hpp"

namespace serialkeymanager_com {

class ActivateError : public std::exception {
private:
  int reason_;

  ActivateError(int reason)
  : reason_(reason) { }
public:
  static const int UNKNOWN_SERVER_REPLY      = 0;
  static const int INVALID_ACCESS_TOKEN      = 1;
  static const int ACCESS_DENIED             = 2;
  static const int INCORRECT_INPUT_PARAMETER = 3;
  static const int PRODUCT_NOT_FOUND         = 4;
  static const int KEY_NOT_FOUND             = 5;
  static const int KEY_BLOCKED               = 6;
  static const int DEVICE_LIMIT_REACHED      = 7;
  static const int SIGNATURE_CHECK_FAILED    = 8;
  static const int JSON_PARSE_FAILED         = 9;

  static ActivateError from_reason(int reason);

  static ActivateError from_server_response(const char *server_response);

  int get_reason();

  virtual const char * what() const noexcept;
};

} // namespace serialkeymanager_com
