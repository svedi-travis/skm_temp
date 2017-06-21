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
  // Every other method has to check for error
  // since this is the constructor
  this->curl = curl_easy_init();
}

std::string
RequestHandler_curl::make_request
  ( Error & e
  , std::string const& url
  )
{
  if (e) { return ""; }

  if (this->curl == NULL) { e.set(Error::MAKE_REQUEST_CURL_NULL); return ""; }

  std::string response;
  CURLcode cc;

  cc = curl_easy_setopt(this->curl, CURLOPT_URL, url.c_str());
  if (cc != CURL_OK) { e.set(Error::MAKE_REQUEST_SETOPT); return ""; }
  cc = curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, handle_response);
  if (cc != CURL_OK) { e.set(Error::MAKE_REQUEST_SETOPT); return ""; }
  cc = curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)&response);
  if (cc != CURL_OK) { e.set(Error::MAKE_REQUEST_SETOPT); return ""; }

  // FIXME: Temporary addition since we are doing cryptographic check
  //        in the library aswell.
  curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYPEER, 0);
  if (cc != CURL_OK) { e.set(Error::MAKE_REQUEST_SETOPT); return ""; }
  curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYHOST, 0);
  if (cc != CURL_OK) { e.set(Error::MAKE_REQUEST_SETOPT); return ""; }

  // FIXME: Non-void return
  cc = curl_easy_perform(this->curl);
  if (cc != CURL_OK) { e.set(Error::MAKE_REQUEST_PERFORM); return ""; }

  return response;
}

RequestHandler_curl::~RequestHandler_curl()
{
  // void return type
  curl_easy_cleanup(this->curl);
}

} // namespace serialkeymanager_com
