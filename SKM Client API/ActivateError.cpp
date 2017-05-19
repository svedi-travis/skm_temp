#include <cstring>

#include "ActivateError.hpp"

namespace serialkeymanager_com {
	
int
ActivateError::get_reason()
{
  return reason_;
}

ActivateError
ActivateError::from_reason(int reason)
{
  return ActivateError(reason);
}

ActivateError
ActivateError::from_server_response(const char *server_response)
{
  int reason = UNKNOWN_SERVER_REPLY;
  if (server_response == nullptr) { return ActivateError(reason); }

  if (0 == std::strcmp(server_response, "Unable to authenticate.")) {
    reason = INVALID_ACCESS_TOKEN;
  }

  if (0 == std::strcmp(server_response, "Access denied.")) {
    reason = ACCESS_DENIED;
  }

  if (0 == std::strcmp(server_response, "The input parameters were incorrect.")) {
    reason = INCORRECT_INPUT_PARAMETER;
  }

  if (0 == std::strcmp(server_response, "Could not find the product.")) {
    reason = PRODUCT_NOT_FOUND;
  }

  if (0 == std::strcmp(server_response, "Could not find the key.")) {
    reason = KEY_NOT_FOUND;
  }

  if (0 == std::strcmp(server_response, "The key is blocked and cannot be accessed.")) {
    reason = KEY_BLOCKED;
  }

  if (0 == std::strcmp(server_response, "Cannot activate the new device as the limit has been reached.")) {
    reason = DEVICE_LIMIT_REACHED;
  }

  return ActivateError(reason);
}

const char *
ActivateError::what() const noexcept
{
  switch (reason_) {
  case INVALID_ACCESS_TOKEN:
  return "Invalid access token.";

  case UNKNOWN_SERVER_REPLY:
  return "Recieved unknown reply from the server.";

  case ACCESS_DENIED:
  return "Access denied.";

  case INCORRECT_INPUT_PARAMETER:
  return "The input parameters were incorrect.";

  case PRODUCT_NOT_FOUND:
  return "Could not find the product." ;

  case KEY_NOT_FOUND:
  return "Could not find the key.";

  case KEY_BLOCKED:
  return "The key is blocked and cannot be accessed.";

  case DEVICE_LIMIT_REACHED:
  return "Cannot activate the new device as the limit has been reached.";

  case SIGNATURE_CHECK_FAILED:
  return "Failed to verify signature of license key.";

  case JSON_PARSE_FAILED:
  return "Failed to parse json response from server.";

  default:
  return "Unknown error.";
  }
}

} // namespace serialkeymanager_com
