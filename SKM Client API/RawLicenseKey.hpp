#pragma once

#include <string>

#include "base64.hpp"
#include "Error.hpp"
#include "optional.hpp"

namespace serialkeymanager_com {

// This class represents a raw reply from the SKM Web API with
// a license key.
//
// This file cannot be queried directly, instead a LicenseKey
// object must be created using something like:
//
//   LicenseKey key = LicenseKey::make(raw.get_license())
//
class RawLicenseKey {
  RawLicenseKey
    ( std::string base64_license
    , std::string signature 
    , std::string decoded_license
    )
  : base64_license_(std::move(base64_license))
  , signature_(std::move(signature))
  , license_(std::move(decoded_license))
  { }

  std::string base64_license_;
  std::string signature_;
  std::string license_;
public:
  std::string const& get_base64_license() const { return base64_license_; }

  std::string const& get_signature() const { return signature_; }

  std::string const& get_license() const { return license_; }

  template<typename SignatureVerifier>
  static
  optional<RawLicenseKey>
  make
    ( Error & e
    , SignatureVerifier const& verifier
    , std::string base64_license
    , std::string signature
    )
  {
    if (e) { return nullopt; }

    // FIXME: Error handling here
    optional<std::string> decoded = b64_decode(base64_license);

    if (!decoded) {
      return nullopt;
    }

    if (verifier.verify_message(e, *decoded, signature)) {
      return make_optional(
        RawLicenseKey
          ( std::move(base64_license)
          , std::move(signature)
          , std::move(*decoded)
          )
        );
    } else {
      return nullopt;
    }
  }
};

} // namespace serialkeymanager_com
