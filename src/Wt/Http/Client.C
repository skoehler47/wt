/*
 * Copyright (C) 2009 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

// bugfix for https://svn.boost.org/trac/boost/ticket/5722
#include <Wt/AsioWrapper/asio.hpp>

#include "Wt/Http/Client.h"
#include "Wt/WApplication.h"
#include "Wt/WIOService.h"
#include "Wt/WEnvironment.h"
#include "Wt/WLogger.h"
#include "Wt/WServer.h"
#include "Wt/Utils.h"

#include "web/WebController.h"
#include "web/WebSession.h"
#include "web/WebUtils.h"

#include <atomic>
#include <memory>
#include <sstream>
#include <boost/algorithm/string.hpp>

#ifdef WT_THREADED
#include <mutex>
#endif // WT_THREADED

#ifdef WT_WITH_SSL

#include <Wt/AsioWrapper/ssl.hpp>
#include "web/SslUtils.h"

#endif // WT_WITH_SSL

#ifdef WT_WIN32
#define strcasecmp _stricmp
#endif

using Wt::AsioWrapper::asio::ip::tcp;

namespace {
constexpr const int STATUS_NO_CONTENT = 204;
constexpr const int STATUS_MOVED_PERMANENTLY = 301;
constexpr const int STATUS_FOUND = 302;
constexpr const int STATUS_SEE_OTHER = 303;
constexpr const int STATUS_TEMPORARY_REDIRECT = 307;
}

namespace Wt {

namespace asio = AsioWrapper::asio;

LOGGER("Http.Client");

  namespace Http {

class Client::Core : public std::enable_shared_from_this<Client::Core>
{
public:

  Core();
  Core(Wt::AsioWrapper::asio::io_service& ioService);
  ~Core();

  void notifyClientDestructed();

  void setTimeout(std::chrono::steady_clock::duration timeout);
  std::chrono::steady_clock::duration timeout() const;
  void setMaximumResponseSize(std::size_t bytes);
  std::size_t maximumResponseSize() const;
  void setSslCertificateVerificationEnabled(bool enabled);
  bool isSslCertificateVerificationEnabled() const;
  void setSslVerifyFile(const std::string& verifyFile);
  void setSslVerifyPath(const std::string& verifyPath);

  bool get(const std::string& url);
  bool get(const std::string& url, const std::vector<Message::Header>& headers);
  bool head(const std::string &url);
  bool head(const std::string &url, const std::vector<Message::Header>& headers);
  bool post(const std::string& url, const Message& message);
  bool put(const std::string& url, const Message& message);
  bool deleteRequest(const std::string& url, const Message& message);
  bool patch(const std::string& url, const Message& message);
  bool request(Http::Method method, const std::string& url, const Message& message);
  void abort();

  Signal<Wt::AsioWrapper::error_code, Message>& done();
  Signal<Message>& headersReceived();
  Signal<std::string>& bodyDataReceived();
  bool followRedirect() const;
  void setFollowRedirect(bool followRedirect);
  int maxRedirects() const;
  void setMaxRedirects(int maxRedirects);

  void handleRedirect(Http::Method method, Wt::AsioWrapper::error_code err,
                      const Message& response, const Message& request);

  void emitDone(Wt::AsioWrapper::error_code err, const Message& response);
  void emitHeadersReceived(const Message& response);  
  void emitBodyReceived(const std::string& data);

private:

  Wt::AsioWrapper::asio::io_service *ioService_;
  std::weak_ptr<Impl> impl_;
#ifdef WT_THREADED
  std::recursive_mutex implementationMutex_;
#endif
  std::chrono::steady_clock::duration timeout_;
  std::size_t maximumResponseSize_;
  bool verifyEnabled_;
  std::string verifyFile_, verifyPath_;
  Signal<Wt::AsioWrapper::error_code, Message> done_;
  Signal<Message> headersReceived_;
  Signal<std::string> bodyDataReceived_;
  bool followRedirect_;
  int redirectCount_;
  int maxRedirects_;
  std::atomic<bool> clientDestructed_;
};

class Client::Impl : public std::enable_shared_from_this<Client::Impl>
{
public:
  struct ChunkState {
    enum class State { Size, Data, Complete, Error } state;
    std::size_t size;
    int parsePos;
  };

  Impl(const std::shared_ptr<Core>& core,
       const std::shared_ptr<WebSession>& session,
       asio::io_service& ioService)
    : ioService_(ioService),
      strand_(ioService),
      resolver_(ioService_),
      method_(Http::Method::Get),
      core_(core),
      session_(session),
      timer_(ioService_),
      timeout_(0),
      maximumResponseSize_(0),
      responseSize_(0),
      postSignals_(session != nullptr),
      aborted_(false)
  { }

  virtual ~Impl() { }

  void setTimeout(std::chrono::steady_clock::duration timeout) {
    timeout_ = timeout;
  }

  void setMaximumResponseSize(std::size_t bytes) {
    maximumResponseSize_ = bytes;
  }

  void request(Http::Method method,
               const std::string& protocol,
               const std::string& auth,
               const std::string& server,
               int port,
               const std::string& path,
               const Message& message)
  {
    const char *methodNames_[] = { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD" };

    method_ = method;
    request_ = message;

    std::ostream request_stream(&requestBuf_);
    request_stream << methodNames_[static_cast<unsigned int>(method)] << " " << path << " HTTP/1.1\r\n";
    if ((protocol == "http" && port == 80) || (protocol == "https" && port == 443))
      request_stream << "Host: " << server << "\r\n";
    else
      request_stream << "Host: " << server << ":"
                     << std::to_string(port) << "\r\n";

    if (!auth.empty())
      request_stream << "Authorization: Basic "
                     << Wt::Utils::base64Encode(auth) << "\r\n";

    bool haveContentLength = false;
    for (unsigned i = 0; i < message.headers().size(); ++i) {
      const Message::Header& h = message.headers()[i];
      if (strcasecmp(h.name().c_str(), "Content-Length") == 0)
        haveContentLength = true;
      request_stream << h.name() << ": " << h.value() << "\r\n";
    }

    if ((method == Http::Method::Post || method == Http::Method::Put || method == Http::Method::Delete || method == Http::Method::Patch) &&
        !haveContentLength)
      request_stream << "Content-Length: " << message.body().length()
                     << "\r\n";

    request_stream << "\r\n";

    if (method == Http::Method::Post || method == Http::Method::Put || method == Http::Method::Delete || method == Http::Method::Patch)
      request_stream << message.body();

    startTimer();
    resolver_.async_resolve
      (server, std::to_string(port),
       strand_.wrap(std::bind(&Impl::handleResolveList,
                              shared_from_this(),
                              std::placeholders::_1,
                              std::placeholders::_2)));
  }

  void asyncStop()
  {
    asio::post(ioService_,
               strand_.wrap(std::bind(&Impl::stop, shared_from_this())));
  }

protected:
  typedef std::function<void(const AsioWrapper::error_code&)>
    ConnectHandler;
  typedef std::function<void(const AsioWrapper::error_code&,
                             const std::size_t&)> IOHandler;

  virtual tcp::socket& socket() = 0;
  virtual void asyncConnect(tcp::endpoint& endpoint,
                            const ConnectHandler& handler) = 0;
  virtual void asyncHandshake(const ConnectHandler& handler) = 0;
  virtual void asyncWriteRequest(const IOHandler& handler) = 0;
  virtual void asyncReadUntil(const std::string& s,
                              const IOHandler& handler) = 0;
  virtual void asyncRead(const IOHandler& handler) = 0;

private:
  void stop()
  {
    /* Within strand */

    aborted_ = true;

    try {
      if (socket().is_open()) {
        AsioWrapper::error_code ignored_ec;
        socket().shutdown(tcp::socket::shutdown_both, ignored_ec);
        socket().close();
      }
    } catch (std::exception& e) {
      LOG_INFO("Client::abort(), stop(), ignoring error: " << e.what());
    }
  }

  void startTimer()
  {
    timer_.expires_after(timeout_);
    timer_.async_wait
      (strand_.wrap(std::bind(&Impl::timeout, shared_from_this(),
                              std::placeholders::_1)));
  }

  void cancelTimer()
  {
    /* Within strand */

    timer_.cancel();
  }

  void timeout(const AsioWrapper::error_code& e)
  {
    /* Within strand */

    if (e != asio::error::operation_aborted) {
      AsioWrapper::error_code ignored_ec;
      socket().shutdown(asio::ip::tcp::socket::shutdown_both,
                        ignored_ec);

      err_ = asio::error::timed_out;
    }
  }

  void handleResolveList(const AsioWrapper::error_code& err,
                       tcp::resolver::results_type endpoints)
  {
    handleResolve(err, endpoints.begin());
  }


  void handleResolve(const AsioWrapper::error_code& err,
                     tcp::resolver::results_type::iterator endpoint_iterator)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // Attempt a connection to the first endpoint in the list.
      // Each endpoint will be tried until we successfully establish
      // a connection.
      tcp::endpoint endpoint = *endpoint_iterator;

      startTimer();
      asyncConnect(endpoint,
                   strand_.wrap(std::bind(&Impl::handleConnect,
                                          shared_from_this(),
                                          std::placeholders::_1,
                                          ++endpoint_iterator)));
    } else {
      if (aborted_)
        err_ = asio::error::operation_aborted;
      else
        err_ = err;
      complete();
    }
  }

  void handleConnect(const AsioWrapper::error_code& err,
                     tcp::resolver::results_type::iterator endpoint_iterator)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // The connection was successful. Do the handshake (SSL only)
      startTimer();
      asyncHandshake
        (strand_.wrap(std::bind(&Impl::handleHandshake,
                                shared_from_this(),
                                std::placeholders::_1)));
    } else if (endpoint_iterator != tcp::resolver::results_type::iterator()) {
      // The connection failed. Try the next endpoint in the list.
      socket().close();

      handleResolve(AsioWrapper::error_code(), endpoint_iterator);
    } else {
      if (aborted_)
        err_ = asio::error::operation_aborted;
      else
        err_ = err;
      complete();
    }
  }

  void handleHandshake(const AsioWrapper::error_code& err)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // The handshake was successful. Send the request.
      startTimer();
      asyncWriteRequest
        (strand_.wrap
         (std::bind(&Impl::handleWriteRequest,
                      shared_from_this(),
                      std::placeholders::_1,
                      std::placeholders::_2)));
    } else {
      if (aborted_)
        err_ = asio::error::operation_aborted;
      else
        err_ = err;
      complete();
    }
  }

  void handleWriteRequest(const AsioWrapper::error_code& err,
                          const std::size_t&)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // Read the response status line.
      startTimer();
      asyncReadUntil
        ("\r\n",
         strand_.wrap
         (std::bind(&Impl::handleReadStatusLine,
                      shared_from_this(),
                      std::placeholders::_1,
                      std::placeholders::_2)));
    } else {
      if (aborted_)
        err_ = asio::error::operation_aborted;
      else
        err_ = err;
      complete();
    }
  }

  bool addResponseSize(std::size_t s)
  {
    responseSize_ += s;

    if (maximumResponseSize_ && responseSize_ > maximumResponseSize_) {
      err_ = asio::error::message_size;
      return false;
    }

    return true;
  }

  void handleReadStatusLine(const AsioWrapper::error_code& err,
                            const std::size_t& s)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      if (!addResponseSize(s)) {
        complete();
        return;
      }

      // Check that response is OK.
      std::istream response_stream(&responseBuf_);
      std::string http_version;
      response_stream >> http_version;
      unsigned int status_code;
      response_stream >> status_code;
      std::string status_message;
      std::getline(response_stream, status_message);
      if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
#ifdef WT_ASIO_IS_BOOST_ASIO
        err_ = boost::system::errc::make_error_code
          (boost::system::errc::protocol_error);
#else
        err_ = std::make_error_code(std::errc::protocol_error);
#endif
        complete();
        return;
      }

      LOG_DEBUG(status_code << " " << status_message);

      response_.setStatus(status_code);

      // Read the response headers, which are terminated by a blank line.
      startTimer();
      asyncReadUntil
        ("\r\n\r\n",
         strand_.wrap
         (std::bind(&Impl::handleReadHeaders,
                      shared_from_this(),
                      std::placeholders::_1,
                      std::placeholders::_2)));
    } else {
      if (aborted_)
        err_ = asio::error::operation_aborted;
      else
        err_ = err;
      complete();
    }
  }

  void handleReadHeaders(const AsioWrapper::error_code& err,
                         const std::size_t& s)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      if (!addResponseSize(s)) {
        complete();
        return;
      }

      chunkedResponse_ = false;
      contentLength_ = -1;

      // Process the response headers.
      std::istream response_stream(&responseBuf_);
      std::string header;
      while (std::getline(response_stream, header) && header != "\r") {
        std::size_t i = header.find(':');
        if (i != std::string::npos) {
          std::string name = boost::trim_copy(header.substr(0, i));
          std::string value = boost::trim_copy(header.substr(i+1));
          response_.addHeader(name, value);

          if (boost::iequals(name, "Transfer-Encoding") &&
              boost::iequals(value, "chunked")) {
            chunkedResponse_ = true;
            chunkState_.size = 0;
            chunkState_.parsePos = 0;
            chunkState_.state = ChunkState::State::Size;
          } else if (method_ != Http::Method::Head &&
                     boost::iequals(name, "Content-Length")) {
            std::stringstream ss(value);
            ss >> contentLength_;
          }
        }
      }

      if (postSignals_) {
        auto session = session_.lock();
        if (session) {
          auto server = session->controller()->server();
          server->post(session->sessionId(),
                       std::bind(&Impl::emitHeadersReceived,
                                 shared_from_this()));
        }
      } else {
        emitHeadersReceived();
      }

      bool done = method_ == Http::Method::Head || response_.status() == STATUS_NO_CONTENT || contentLength_ == 0;
      // Write whatever content we already have to output.
      if (responseBuf_.size() > 0) {
        std::stringstream ss;
        ss << &responseBuf_;
        done = addBodyText(ss.str());
      }

      if (!done) {
        // Start reading remaining data until EOF.
        startTimer();
        asyncRead(strand_.wrap
            (std::bind(&Impl::handleReadContent,
                       shared_from_this(),
                       std::placeholders::_1,
                       std::placeholders::_2)));
      } else {
        complete();
      }
    } else {
      if (!aborted_)
        err_ = asio::error::operation_aborted;
      else
        err_ = err;
      complete();
    }
  }

  void handleReadContent(const AsioWrapper::error_code& err,
                         const std::size_t& s)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      if (!addResponseSize(s)) {
        complete();
        return;
      }

      std::stringstream ss;
      ss << &responseBuf_;

      bool done = addBodyText(ss.str());

      if (!done) {
        // Continue reading remaining data until EOF.
        startTimer();
        asyncRead
          (strand_.wrap
           (std::bind(&Impl::handleReadContent,
                      shared_from_this(),
                      std::placeholders::_1,
                      std::placeholders::_2)));
      } else {
        complete();
      }
    } else if (!aborted_
               && err != asio::error::eof
               && err != asio::error::shut_down
               && err != asio::error::bad_descriptor
               && err != asio::error::operation_aborted
               && err.value() != 335544539) {
      err_ = err;
      complete();
    } else {
      if (aborted_)
        err_ = asio::error::operation_aborted;
      complete();
    }
  }

  // Returns whether we're done (caller must call complete())
  bool addBodyText(const std::string& text)
  {
    if (chunkedResponse_) {
      chunkedDecode(text);
      if (chunkState_.state == ChunkState::State::Error) {
        protocolError();
        return true;
      } else if (chunkState_.state == ChunkState::State::Complete) {
        return true;
      } else
        return false;
    } else {
      if (maximumResponseSize_)
        response_.addBodyText(text);

      LOG_DEBUG("Data: " << text);
      haveBodyData(text);

      return (contentLength_ >= 0) &&
        (static_cast<int>(response_.body().size()) >= contentLength_);
    }
  }

  void chunkedDecode(const std::string& text)
  {
    std::string::const_iterator pos = text.begin();
    while (pos != text.end()) {
      switch (chunkState_.state) {
      case ChunkState::State::Size: {
        unsigned char ch = *(pos++);

        switch (chunkState_.parsePos) {
        case -2:
          if (ch != '\r') {
            chunkState_.state = ChunkState::State::Error; return;
          }

          chunkState_.parsePos = -1;

          break;
        case -1:
          if (ch != '\n') {
            chunkState_.state = ChunkState::State::Error; return;
          }

          chunkState_.parsePos = 0;

          break;
        case 0:
          if (ch >= '0' && ch <= '9') {
            chunkState_.size <<= 4;
            chunkState_.size |= (ch - '0');
          } else if (ch >= 'a' && ch <= 'f') {
            chunkState_.size <<= 4;
            chunkState_.size |= (10 + ch - 'a');
          } else if (ch >= 'A' && ch <= 'F') {
            chunkState_.size <<= 4;
            chunkState_.size |= (10 + ch - 'A');
          } else if (ch == '\r') {
            chunkState_.parsePos = 2;
          } else if (ch == ';') {
            chunkState_.parsePos = 1;
          } else {
             chunkState_.state = ChunkState::State::Error; return;
          }

          break;
        case 1:
          /* Ignoring extensions and syntax for now */
          if (ch == '\r')
            chunkState_.parsePos = 2;

          break;
        case 2:
          if (ch != '\n') {
            chunkState_.state = ChunkState::State::Error; return;
          }

          if (chunkState_.size == 0) {
            chunkState_.state = ChunkState::State::Complete; return;
          }

          chunkState_.state = ChunkState::State::Data;
        }

        break;
      }
      case ChunkState::State::Data: {
        std::size_t thisChunk
          = std::min(std::size_t(text.end() - pos), chunkState_.size);
        std::string text = std::string(pos, pos + thisChunk);
        if (maximumResponseSize_)
          response_.addBodyText(text);

        LOG_DEBUG("Chunked data: " << text);
        haveBodyData(text);
        chunkState_.size -= thisChunk;
        pos += thisChunk;

        if (chunkState_.size == 0) {
          chunkState_.parsePos = -2;
          chunkState_.state = ChunkState::State::Size;
        }
        break;
      }
      default:
        assert(false); // Illegal state
      }
    }
  }

  void protocolError()
  {
#ifdef WT_ASIO_IS_BOOST_ASIO
    err_ = boost::system::errc::make_error_code
      (boost::system::errc::protocol_error);
#else
    err_ = std::make_error_code(std::errc::protocol_error);
#endif
  }

  void complete()
  {
    stop();
    if (postSignals_) {
      auto session = session_.lock();
      if (session) {
        auto server = session->controller()->server();
        server->post(session->sessionId(),
                     std::bind(&Impl::emitDone, shared_from_this()));
      }
    } else {
      emitDone();
    }
  }

  void haveBodyData(std::string text)
  {
    if (postSignals_) {
      auto session = session_.lock();
      if (session) {
        auto server = session->controller()->server();
        server->post(session->sessionId(),
                     std::bind(&Impl::emitBodyReceived, shared_from_this(), text));
      }
    } else {
      emitBodyReceived(text);
    }
  }

  void emitDone()
  {
    if (core_->followRedirect()) {
      core_->handleRedirect(method_,
                              err_,
                              response_,
                              request_);
    } else {
      core_->emitDone(err_, response_);
    }
  }

  void emitHeadersReceived() {
    core_->emitHeadersReceived(response_);
  }

  void emitBodyReceived(const std::string& text) {
    core_->emitBodyReceived(text);
  }

protected:
  asio::io_service& ioService_;
  AsioWrapper::strand strand_;
  tcp::resolver resolver_;
  asio::streambuf requestBuf_;
  asio::streambuf responseBuf_;
  Http::Message request_;
  Http::Method method_;

private:
  std::shared_ptr<Core> core_;
  std::weak_ptr<WebSession> session_;
  asio::steady_timer timer_;
  std::chrono::steady_clock::duration timeout_;
  std::size_t maximumResponseSize_, responseSize_;
  bool chunkedResponse_;
  ChunkState chunkState_;
  int contentLength_;
  AsioWrapper::error_code err_;
  Message response_;
  bool postSignals_;
  bool aborted_;
};

class Client::TcpImpl final : public Client::Impl
{
public:
  TcpImpl(const std::shared_ptr<Core>& core,
          const std::shared_ptr<WebSession>& session,
          asio::io_service& ioService)
    : Impl(core, session, ioService),
      socket_(ioService_)
  { }

protected:
  virtual tcp::socket& socket() override
  {
    return socket_;
  }

  virtual void asyncConnect(tcp::endpoint& endpoint,
                            const ConnectHandler& handler) override
  {
    socket_.async_connect(endpoint, handler);
  }

  virtual void asyncHandshake(const ConnectHandler& handler) override
  {
    handler(AsioWrapper::error_code());
  }

  virtual void asyncWriteRequest(const IOHandler& handler) override
  {
    asio::async_write(socket_, requestBuf_, handler);
  }

  virtual void asyncReadUntil(const std::string& s,
                              const IOHandler& handler) override
  {
    asio::async_read_until(socket_, responseBuf_, s, handler);
  }

  virtual void asyncRead(const IOHandler& handler) override
  {
    asio::async_read(socket_, responseBuf_,
                            asio::transfer_at_least(1), handler);
  }

private:
  tcp::socket socket_;
};

#ifdef WT_WITH_SSL

class Client::SslImpl final : public Client::Impl
{
public:
  SslImpl(const std::shared_ptr<Core>& core,
          const std::shared_ptr<WebSession>& session,
          asio::io_service& ioService,
          bool verifyEnabled,
          asio::ssl::context& context,
          const std::string& hostName)
    : Impl(core, session, ioService),
      socket_(ioService_, context),
      verifyEnabled_(verifyEnabled),
      hostName_(hostName)
  {
#ifndef OPENSSL_NO_TLSEXT
    if (!SSL_set_tlsext_host_name(socket_.native_handle(), hostName.c_str())) {
      LOG_ERROR("could not set tlsext host.");
    }
#endif
  }

protected:
  virtual tcp::socket& socket() override
  {
    return socket_.next_layer();
  }

  virtual void asyncConnect(tcp::endpoint& endpoint,
                            const ConnectHandler& handler) override
  {
    socket_.lowest_layer().async_connect(endpoint, handler);
  }

  virtual void asyncHandshake(const ConnectHandler& handler) override
  {
    if (verifyEnabled_) {
      socket_.set_verify_mode(asio::ssl::verify_peer);
      LOG_DEBUG("verifying that peer is " << hostName_);
      socket_.set_verify_callback
        (asio::ssl::rfc2818_verification(hostName_));
    }
    socket_.async_handshake(asio::ssl::stream_base::client, handler);
  }

  virtual void asyncWriteRequest(const IOHandler& handler) override
  {
    asio::async_write(socket_, requestBuf_, handler);
  }

  virtual void asyncReadUntil(const std::string& s,
                              const IOHandler& handler) override
  {
    asio::async_read_until(socket_, responseBuf_, s, handler);
  }

  virtual void asyncRead(const IOHandler& handler) override
  {
    asio::async_read(socket_, responseBuf_,
                            asio::transfer_at_least(1), handler);
  }

private:
  typedef asio::ssl::stream<tcp::socket> ssl_socket;

  ssl_socket socket_;
  bool verifyEnabled_;
  std::string hostName_;
};
#endif // WT_WITH_SSL



Client::Core::Core()
  : ioService_(nullptr),
    timeout_(std::chrono::seconds{10}),
    maximumResponseSize_(64*1024),
#ifdef WT_WITH_SSL
    verifyEnabled_(true),
#else
    verifyEnabled_(false),
#endif
    followRedirect_(false),
    redirectCount_(0),
    maxRedirects_(20),
    clientDestructed_(false)
{ }

Client::Core::Core(Wt::AsioWrapper::asio::io_service& ioService)
  : ioService_(&ioService),
    timeout_(std::chrono::seconds{10}),
    maximumResponseSize_(64*1024),
#ifdef WT_WITH_SSL
    verifyEnabled_(true),
#else
    verifyEnabled_(false),
#endif
    followRedirect_(false),
    redirectCount_(0),
    maxRedirects_(20),
    clientDestructed_(false)
{ }

Client::Core::~Core()
{ }

void Client::Core::notifyClientDestructed()
{
  clientDestructed_ = true;
}

void Client::Core::setTimeout(std::chrono::steady_clock::duration timeout)
{
  timeout_ = timeout;
}

std::chrono::steady_clock::duration Client::Core::timeout() const
{
  return timeout_;
}

void Client::Core::setMaximumResponseSize(std::size_t bytes)
{
  maximumResponseSize_ = bytes;
}

std::size_t Client::Core::maximumResponseSize() const
{
  return maximumResponseSize_; 
}

void Client::Core::setSslCertificateVerificationEnabled(bool enabled)
{
    verifyEnabled_ = enabled;
}

bool Client::Core::isSslCertificateVerificationEnabled() const
{
    return verifyEnabled_;
}

void Client::Core::setSslVerifyFile(const std::string& verifyFile)
{
  verifyFile_ = verifyFile;
}

void Client::Core::setSslVerifyPath(const std::string& verifyPath)
{
  verifyPath_ = verifyPath;
}

bool Client::Core::get(const std::string& url)
{
  return request(Http::Method::Get, url, Message());
}

bool Client::Core::get(const std::string& url, const std::vector<Message::Header>& headers)
{
  Message m(headers);
  return request(Http::Method::Get, url, m);
}

bool Client::Core::head(const std::string &url)
{
  return request(Http::Method::Head, url, Message());
}

bool Client::Core::head(const std::string &url, const std::vector<Message::Header>& headers)
{
  Message m(headers);
  return request(Http::Method::Head, url, m);
}

bool Client::Core::post(const std::string& url, const Message& message)
{
  return request(Http::Method::Post, url, message);
}

bool Client::Core::put(const std::string& url, const Message& message)
{
  return request(Http::Method::Put, url, message);
}

bool Client::Core::deleteRequest(const std::string& url, const Message& message)
{
  return request(Http::Method::Delete, url, message);
}

bool Client::Core::patch(const std::string& url, const Message& message)
{
  return request(Http::Method::Patch, url, message);
}

bool Client::Core::request(Http::Method method, const std::string& url, const Message& message)
{
  asio::io_service *ioService = ioService_;

  WApplication *app = WApplication::instance();

  auto impl = impl_.lock();
  if (impl) {
    LOG_ERROR("another request is in progress");
    return false;
  }

  WebSession *session = nullptr;

  if (app && !ioService) {
    // Use WServer's IO service, and post events to WApplication
    session = app->session();
    auto server = session->controller()->server();
    ioService = &server->ioService();
  } else if (!ioService) {
    // Take IO service from server
    auto server = WServer::instance();

    if (server)
      ioService = &server->ioService();
    else {
      LOG_ERROR("requires a WIOService for async I/O");
      return false;
    }
  }

  URL parsedUrl;

  if (!parseUrl(url, parsedUrl))
    return false;

  if (parsedUrl.protocol == "http") {
    impl = std::make_shared<TcpImpl>(shared_from_this(),
                                     session ? session->shared_from_this() : nullptr,
                                     *ioService);
    impl_ = impl;

#ifdef WT_WITH_SSL
  } else if (parsedUrl.protocol == "https") {
    asio::ssl::context context = Ssl::createSslContext(*ioService, verifyEnabled_);

    if (!verifyFile_.empty() || !verifyPath_.empty()) {
      if (!verifyFile_.empty())
        context.load_verify_file(verifyFile_);
      if (!verifyPath_.empty())
        context.add_verify_path(verifyPath_);
    }

    impl = std::make_shared<SslImpl>(shared_from_this(),
                                     session ? session->shared_from_this() : nullptr,
                                     *ioService,
                                     verifyEnabled_,
                                     context,
                                     parsedUrl.host);
    impl_ = impl;
#endif // WT_WITH_SSL

  } else {
    LOG_ERROR("unsupported protocol: " << parsedUrl.protocol);
    return false;
  }

  impl->setTimeout(timeout_);
  impl->setMaximumResponseSize(maximumResponseSize_);

  impl->request(method,
                parsedUrl.protocol,
                parsedUrl.auth,
                parsedUrl.host,
                parsedUrl.port,
                parsedUrl.path,
                message);

  return true;
}

void Client::Core::abort()
{
#ifdef WT_THREADED
  std::unique_lock<std::recursive_mutex> lock(implementationMutex_);
#endif

  std::shared_ptr<Impl> impl = impl_.lock();
  if (impl) {
    impl->asyncStop();
  }
}

Signal<Wt::AsioWrapper::error_code, Message>& Client::Core::done()
{
  return done_;
}

Signal<Message>& Client::Core::headersReceived()
{
  return headersReceived_;
}

Signal<std::string>& Client::Core::bodyDataReceived()
{
  return bodyDataReceived_;
}

bool Client::Core::followRedirect() const
{
  return followRedirect_;
}

void Client::Core::setFollowRedirect(bool followRedirect)
{
  followRedirect_ = followRedirect;
}

int Client::Core::maxRedirects() const
{
  return maxRedirects_;
}

void Client::Core::setMaxRedirects(int maxRedirects)
{
  maxRedirects_ = maxRedirects;
}

void Client::Core::handleRedirect(Http::Method method, Wt::AsioWrapper::error_code err,
                    const Message& response, const Message& request)
{
  // abort if client has already been destructed
  if (clientDestructed_) { return; }

#ifdef WT_THREADED
  std::unique_lock<std::recursive_mutex> lock(implementationMutex_);
#endif
  impl_.reset();
  int status = response.status();
  if (!err && (((status == STATUS_MOVED_PERMANENTLY ||
                status == STATUS_FOUND ||
                status == STATUS_TEMPORARY_REDIRECT) && method == Http::Method::Get) ||
              status == STATUS_SEE_OTHER)) {
    const std::string *newUrl = response.getHeader("Location");
    ++ redirectCount_;
    if (newUrl) {
      if (redirectCount_ <= maxRedirects_) {
        get(*newUrl, request.headers());
        return;
      } else {
        LOG_WARN("Redirect count of " << maxRedirects_
                << " exceeded! Redirect URL: " << *newUrl);
      }
    }
  }
  emitDone(err, response);
}

void Client::Core::emitDone(Wt::AsioWrapper::error_code err, const Message& response)
{
#ifdef WT_THREADED
  std::unique_lock<std::recursive_mutex> lock(implementationMutex_);
#endif
  
  impl_.reset();
  redirectCount_ = 0;

  // abort if client has already been destructed
  if (clientDestructed_) { return; }

  done_.emit(err, response);
}
  
void Client::Core::emitHeadersReceived(const Message& response)
{
  // abort if client has already been destructed
  if (clientDestructed_) { return; }

  /*
   * The response cannot be completely copied here, because another
   * thread may be writting its body (see issue #13714).
   */
  headersReceived_.emit(Message(response.headers(), response.status()));
}

void Client::Core::emitBodyReceived(const std::string& data)
{
  // abort if client has already been destructed
  if (clientDestructed_) { return; }

  bodyDataReceived_.emit(data);
}



Client::Client()
  : core_(std::make_shared<Core>())
{ }

Client::Client(asio::io_service& ioService)
  : core_(std::make_shared<Core>(ioService))
{ }

Client::~Client()
{
  core_->notifyClientDestructed();
  core_->abort();
}

void Client::abort()
{
  core_->abort();
}

void Client::setTimeout(std::chrono::steady_clock::duration timeout)
{
  core_->setTimeout(timeout);
}

std::chrono::steady_clock::duration Client::timeout() const
{
  return core_->timeout();
}

void Client::setMaximumResponseSize(std::size_t bytes)
{
  core_->setMaximumResponseSize(bytes);
}

std::size_t Client::maximumResponseSize() const
{
  return core_->maximumResponseSize(); 
}

void Client::setSslCertificateVerificationEnabled(bool enabled)
{
  core_->setSslCertificateVerificationEnabled(enabled);
}

bool Client::isSslCertificateVerificationEnabled() const
{
  return core_->isSslCertificateVerificationEnabled();
}

void Client::setSslVerifyFile(const std::string& verifyFile)
{
  core_->setSslVerifyFile(verifyFile);
}

void Client::setSslVerifyPath(const std::string& verifyPath)
{
  core_->setSslVerifyPath(verifyPath);
}

bool Client::get(const std::string& url)
{
  return core_->get(url);
}

bool Client::get(const std::string& url,
                 const std::vector<Message::Header> headers)
{
  return core_->get(url, headers);
}

bool Client::head(const std::string& url)
{
  return core_->head(url);
}

bool Client::head(const std::string& url,
                  const std::vector<Message::Header> headers)
{
  return core_->head(url, headers);
}

bool Client::post(const std::string& url, const Message& message)
{
  return core_->post(url, message);
}

bool Client::put(const std::string& url, const Message& message)
{
  return core_->put(url, message);
}

bool Client::deleteRequest(const std::string& url, const Message& message)
{
  return core_->deleteRequest(url, message);
}

bool Client::patch(const std::string& url, const Message& message)
{
  return core_->patch(url, message);
}

bool Client::request(Http::Method method, const std::string& url,
                     const Message& message)
{
  return core_->request(method, url, message); 
}

Signal<Wt::AsioWrapper::error_code, Message>& Client::done()
{
  return core_->done();
}

Signal<Message>& Client::headersReceived()
{
  return core_->headersReceived();
}

Signal<std::string>& Client::bodyDataReceived()
{
  return core_->bodyDataReceived();
}

bool Client::followRedirect() const
{
  return core_->followRedirect();
}

void Client::setFollowRedirect(bool followRedirect)
{
  core_->setFollowRedirect(followRedirect);
}

int Client::maxRedirects() const
{
  return core_->maxRedirects();
}

void Client::setMaxRedirects(int maxRedirects)
{
  core_->setMaxRedirects(maxRedirects);
}

bool Client::parseUrl(const std::string &url, URL &parsedUrl)
{
  std::size_t i = url.find("://");
  if (i == std::string::npos) {
    LOG_ERROR("ill-formed URL: " << url);
    return false;
  }

  parsedUrl.protocol = url.substr(0, i);
  std::string rest = url.substr(i + 3);
  // find auth
  std::size_t l = rest.find('@');
  // find host
  std::size_t j = rest.find('/');
  if (l != std::string::npos &&
      (j == std::string::npos || j > l)) {
    // above check: userinfo can not contain a forward slash
    // path may contain @ (issue #7272)
    parsedUrl.auth = rest.substr(0, l);
    parsedUrl.auth = Wt::Utils::urlDecode(parsedUrl.auth);
    rest = rest.substr(l+1);
    if (j != std::string::npos) {
      j -= l + 1;
    }
  }

  if (j == std::string::npos) {
    parsedUrl.host = rest;
    parsedUrl.path = "/";
  } else {
    parsedUrl.host = rest.substr(0, j);
    parsedUrl.path = rest.substr(j);
  }

  std::size_t k = parsedUrl.host.find(':');
  if (k != std::string::npos) {
    try {
      parsedUrl.port = Utils::stoi(parsedUrl.host.substr(k + 1));
    } catch (std::exception& e) {
      LOG_ERROR("invalid port: " << parsedUrl.host.substr(k + 1));
      return false;
    }
    parsedUrl.host = parsedUrl.host.substr(0, k);
  } else {
    if (parsedUrl.protocol == "http")
      parsedUrl.port = 80;
    else if (parsedUrl.protocol == "https")
      parsedUrl.port = 443;
    else
      parsedUrl.port = 80; // protocol will not be handled anyway
  }

  return true;
}

  }
}
