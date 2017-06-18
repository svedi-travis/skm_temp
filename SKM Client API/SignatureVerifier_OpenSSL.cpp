#include <string>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "SignatureVerifier_OpenSSL.hpp"
#include "base64.hpp"
#include "optional.hpp"

namespace serialkeymanager_com {

int
verify(RSA * rsa, std::string const& message, std::string const& sig)
{
  int r;

  if (rsa == NULL) { return 0; }

  EVP_MD_CTX * ctx = EVP_MD_CTX_create();
  if (ctx == NULL) { return 0; }

  EVP_PKEY * pkey = EVP_PKEY_new();
  if (pkey == NULL) { return 0; }

  r = EVP_PKEY_set1_RSA(pkey, rsa);
  if (r != 1) { return 0; }



  r = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
  if (r != 1) { return 0; }

  r = EVP_DigestVerifyUpdate(ctx, (unsigned char*)message.c_str(), message.size());
  if (r != 1) { return 0; }

  r = EVP_DigestVerifyFinal(ctx, (unsigned char*)sig.c_str(), sig.size());

  // void return type
  EVP_PKEY_free(pkey);

  // void return type
  EVP_MD_CTX_destroy(ctx);

  return r;
}

SignatureVerifier_OpenSSL::SignatureVerifier_OpenSSL()
{
  this->rsa = RSA_new();
  if (this->rsa != NULL) {
    this->rsa->n = BN_new();
    if (this->rsa->n == NULL) { RSA_free(this->rsa); }

    this->rsa->e = BN_new();
    if (this->rsa->e == NULL) { RSA_free(this->rsa); }
  }
}

SignatureVerifier_OpenSSL::~SignatureVerifier_OpenSSL()
{
  if (this->rsa != NULL) {
    // void return type
    RSA_free(this->rsa);
  }
}

void
SignatureVerifier_OpenSSL::set_modulus_base64
  ( Error & e
  , std::string const& modulus_base64
  )
{
  if (e) { return; }

  if (this->rsa == NULL) { return; }

  optional<std::string> modulus = b64_decode(modulus_base64);
  if (!modulus) { return; }

  // FIXME: non-void return type
  BN_bin2bn((unsigned char*)modulus->c_str(),  modulus->size(),  this->rsa->n);
}

void
SignatureVerifier_OpenSSL::set_exponent_base64
  ( Error & e
  , std::string const& exponent_base64
  )
{
  if (e) { return; }

  if (this->rsa == NULL) { return; }

  optional<std::string> exponent = b64_decode(exponent_base64);
  if (!exponent) { return; }

  // FIXME: non-void return type
  BN_bin2bn((unsigned char*)exponent->c_str(), exponent->size(), this->rsa->e);
}

bool
SignatureVerifier_OpenSSL::verify_message
  ( Error & e
  , std::string const& message
  , std::string const& signature_base64
  )
const
{
  if (e) { return false; }

  if (this->rsa == NULL) { return false; }

  optional<std::string> sig = b64_decode(signature_base64);
  if (!sig) { return false; }
		 
  // Note, anything but 1 from verify is failure, thus != is important
  if (verify(this->rsa, message, *sig) != 1) { return false; }
  else                                       { return true; }
}

} // namespace serialkeymanager_com
