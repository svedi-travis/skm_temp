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
public:
  Error(size_t reason)
  : reason_(reason) { }

  static constexpr size_t NO_ERROR = 0;

  explicit operator bool() const { return reason_ != NO_ERROR; }

  size_t get_reason() const noexcept { return reason_; }
};

} // namespace serialkeymanager_com
