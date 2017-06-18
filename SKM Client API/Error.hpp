#pragma once

namespace serialkeymanager_com {

class Error {
// Big changes:
//  * SignatureVerifier_OpenSSL::verify_message() return bool -> int

// Annat:
//  * Hantera timeouts fran server etc


// Vad kan skicka error:
//  * decode base64
//  * curl url building
//  * curl_easy_init
//  * curl_easy_setopt
//  * curl when reading the response
//  * Different functions when verifying (openssl)
//  * Setting modulus/exponent
private:
  size_t reason_;

  Error(size_t reason)
  : reason_(reason), source(SOURCE_OK) { }
public:
  size_t source;
  static const size_t SOURCE_OK                 = 0;

  explicit operator bool() const { return source != SOURCE_OK; }

  static const size_t UNKNOWN_SERVER_REPLY      = 0;
  static const size_t INVALID_ACCESS_TOKEN      = 1;
  static const size_t ACCESS_DENIED             = 2;
  static const size_t INCORRECT_INPUT_PARAMETER = 3;
  static const size_t PRODUCT_NOT_FOUND         = 4;
  static const size_t KEY_NOT_FOUND             = 5;
  static const size_t KEY_BLOCKED               = 6;
  static const size_t DEVICE_LIMIT_REACHED      = 7;
  static const size_t SIGNATURE_CHECK_FAILED    = 8;
  static const size_t JSON_PARSE_FAILED         = 9;

  static Error from_reason(size_t reason) { return Error(reason); }

  size_t get_reason() const noexcept;
};

} // namespace serialkeymanager_com
