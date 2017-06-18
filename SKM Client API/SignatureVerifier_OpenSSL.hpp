#pragma once

#include <string>

#include <openssl/rsa.h>

namespace serialkeymanager_com {

// A signature verifier built around the OpenSSL library.
class SignatureVerifier_OpenSSL
{
public:
  SignatureVerifier_OpenSSL();

  ~SignatureVerifier_OpenSSL();

  // Set the modulus, found under Security Settings on serialkeymanager.com
  int set_modulus_base64(std::string const& modulus_base64);

  // Set the exponent, found under Security Settings on serialkeymanager.com
  int set_exponent_base64(std::string const& exponent_base64);

  // Verifies that the message is correct using the provided signature
  bool verify_message(std::string const& message, std::string const& signature_base64) const;
  int  verify_message_new(std::string const& message, std::string const& signature_base64) const;

private:
  RSA * rsa;
};

} // namespace serialkeymanager_com
