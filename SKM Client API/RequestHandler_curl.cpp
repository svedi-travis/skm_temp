#include <curl/curl.h>

#include "RequestHandler_curl.hpp"

namespace serialkeymanager_com {

size_t
handle_response(char * ptr, size_t size, size_t nmemb, void *userdata)
{
  // FIXME: This can throw I guess
  std::string current{ptr, size*nmemb};

  // FIXME: This can throw I guess
  std::string *response = (std::string *)userdata;
  *response += current;

  return size*nmemb;
}

RequestHandler_curl::RequestHandler_curl()
{
  // FIXME: Non-void return
  this->curl = curl_easy_init();
}

std::string
RequestHandler_curl::make_request(Error e, std::string const& url)
{
  std::string response;

  // FIXME: Non-void return
  curl_easy_setopt(this->curl, CURLOPT_URL, url.c_str());
  // FIXME: Non-void return
  curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, handle_response);
  // FIXME: Non-void return
  curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&response);

  // FIXME: Temporary addition since we are doing cryptographic check
  //        in the library aswell.
  // FIXME: Non-void return
  curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYPEER, 0);
  // FIXME: Non-void return
  curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYHOST, 0);

  // FIXME: Non-void return
  curl_easy_perform(this->curl);

  return response;
}

RequestHandler_curl::~RequestHandler_curl()
{
  // void return type
  curl_easy_cleanup(this->curl);
}

} // namespace serialkeymanager_com
