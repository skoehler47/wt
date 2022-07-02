/*
 * Copyright (C) 2008 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include <fstream>

#include <boost/algorithm/string.hpp>

#ifdef WT_THREADED
#include <chrono>
#endif // WT_THREADED

#include "Wt/Utils.h"
#include "Wt/WApplication.h"
#include "Wt/WEvent.h"
#include "Wt/WRandom.h"
#include "Wt/WResource.h"
#include "Wt/WServer.h"
#include "Wt/WSocketNotifier.h"
#include "Wt/WWebSocketResource.h"

#include "Configuration.h"
#include "CgiParser.h"
#include "WebController.h"
#include "WebRequest.h"
#include "WebSession.h"
#include "TimeUtil.h"
#include "WebUtils.h"

#ifdef HAVE_GRAPHICSMAGICK
#include <magick/api.h>
#endif

#include <boost/utility/string_view.hpp>

#include <algorithm>
#include <csignal>

#define WT_REDIRECT_SECRET_HEADER "X-Wt-Redirect-Secret"

namespace {
  std::string str(const std::string *strPtr)
  {
    if (strPtr) {
      return *strPtr;
    } else {
      return std::string();
    }
  }
}

namespace Wt {

LOGGER("WebController");

WebController::WebController(WServer& server,
                             const std::string& singleSessionId,
                             bool autoExpire)
  : conf_(server.configuration()),
    singleSessionId_(singleSessionId),
    autoExpire_(autoExpire),
    plainHtmlSessions_(0),
    ajaxSessions_(0),
    zombieSessions_(0),
    running_(false),
#ifdef WT_THREADED
    socketNotifier_(this),
#endif // WT_THREADED
    server_(server)
{
#ifndef WT_DEBUG_JS
  WObject::seedId(WRandom::get());
#else
  WObject::seedId(0);
#endif

  redirectSecret_ = WRandom::generateId(32);

#ifdef HAVE_GRAPHICSMAGICK
  InitializeMagick(0);
#endif

#ifdef WT_THREADED
  // initialize expiring_t to 'false'
  expiring_.clear();
#endif

  start();
}

WebController::~WebController()
{
#ifdef HAVE_GRAPHICSMAGICK
  DestroyMagick();
#endif
}

void WebController::start()
{
  running_ = true;
}

void WebController::shutdown()
{
  {
    std::vector<std::shared_ptr<WebSession>> sessionList;

    {
#ifdef WT_THREADED
      /* write lock */
      std::unique_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

      running_ = false;

      LOG_INFO_S(&server_, "shutdown: stopping " << sessions_.size()
                 << " sessions.");

      for (auto s : sessions_) {
        sessionList.push_back(s.second);
      }

      sessions_.clear();

      ajaxSessions_ = 0;
      plainHtmlSessions_ = 0;
    }

    for (auto& session : sessionList) {
      WebSession::Handler handler(session,
                                  WebSession::Handler::LockOption::TakeLock);
      session->expire();
    }
  }

#ifdef WT_THREADED
  while (zombieSessions_ > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
#endif
}

void WebController::sessionDeleted()
{
  --zombieSessions_;
}

Configuration& WebController::configuration()
{
  return conf_;
}

const Configuration& WebController::configuration() const
{
  return conf_;
}

int WebController::sessionCount() const
{
#ifdef WT_THREADED
  /* read lock */
  std::shared_lock<mutex_t> lock{ mutex_ };
#endif
  return sessions_.size();
}

std::vector<std::string> WebController::sessions(bool onlyRendered)
{
#ifdef WT_THREADED
  /* read lock */
  std::shared_lock<mutex_t> lock{ mutex_ };
#endif
  std::vector<std::string> sessionIds;
  for (SessionMap::const_iterator i = sessions_.begin(); i != sessions_.end(); ++i) {
    if (!onlyRendered || i->second->app() != nullptr) {
      sessionIds.push_back(i->first);
    }
  }
  return sessionIds;
}

void WebController::expireSessions(bool force)
{
#ifdef WT_THREADED
  if (!expiring_.test_and_set() || force) {
  // check 'force' last to ensure 'expiring_' flag gets properly set
#endif // WT_THREADED

    std::vector<std::shared_ptr<WebSession>> toExpire;
    {
      Time now;

#ifdef WT_THREADED
      /* read lock */
      std::shared_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

      for (const auto& s : sessions_) {
        const int diff = s.second->expireTime() - now;
        if (diff < 1000 && configuration().sessionTimeout() != -1) {
          toExpire.push_back(s.second);
          // Note: the session is not yet removed from sessions_ map since
          // we want to grab the UpdateLock to do this and grabbing it here
          // might cause a deadlock.
        }
      }
    }

    for(auto& session : toExpire) {

      LOG_INFO_S(session, "timeout: expiring");
      WebSession::Handler handler(session,
                                  WebSession::Handler::LockOption::TakeLock);

#ifdef WT_THREADED
      /* write lock */
      std::unique_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

    // try to delete session from session map; return
    // value will be 0 if element is not found (e.g.
    // if already deleted by another thread), skip
    // expiring session in this case
      if (sessions_.erase(session->sessionId()) == 0) {
        continue;
      }

#ifdef WT_THREADED
      lock.unlock();
#endif // WT_THREADED

      if (session->env().ajax()) {
        --ajaxSessions_;
      } else {
        --plainHtmlSessions_;
      }

      ++zombieSessions_;

      session->expire();
    }

#ifdef WT_THREADED
    expiring_.clear();
  }
#endif  // WT_THREADED
}

void WebController::addSession(const std::shared_ptr<WebSession>& session)
{
#ifdef WT_THREADED
  /* write lock */
  std::unique_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

  sessions_[session->sessionId()] = session;
}

void WebController::removeSession(const std::string& sessionId)
{
  LOG_INFO("Removing session " << sessionId);

#ifdef WT_THREADED
  /* write lock */
  std::unique_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

  SessionMap::const_iterator i = sessions_.find(sessionId);
  if (i != sessions_.end()) {
    ++zombieSessions_;
    if (i->second->env().ajax()) {
      --ajaxSessions_;
    } else {
      --plainHtmlSessions_;
    }
    sessions_.erase(i);
  }
  const bool sessionsEmpty = sessions_.empty();

#ifdef WT_THREADED
  lock.unlock();
#endif // WT_THREADED

  if (server_.dedicatedSessionProcess() && sessionsEmpty) {
    server_.scheduleStop();
  }
}

std::string WebController::appSessionCookie(const std::string& url)
{
  return Utils::urlEncode(url);
}

std::string WebController::sessionFromCookie(const char * const cookies,
                                             const std::string& scriptName,
                                             const int sessionIdLength)
{
  if (!cookies)
    return std::string();

  std::string cookieName = appSessionCookie(scriptName);

  // is_whitespace returns whether a character is whitespace according to RFC 5234 WSP
  auto is_whitespace = [](char c) { return c == ' ' || c == '\t'; };
  auto is_alphanumeric = [](char c) { return (c >= 'A' && c <= 'Z') ||
                                             (c >= 'a' && c <= 'z') ||
                                             (c >= '0' && c <= '9'); };

  const char *start = cookies;
  const char * const end = cookies + strlen(cookies);
  start = std::find_if_not(start, end, is_whitespace); // Skip leading whitespace
  while (start < end) {
    const char *const nextEquals = std::find(start, end, '=');
    if (nextEquals == end)
      return std::string{}; // Cookie header has no equals anymore
    const char *const nextSemicolon = std::find(nextEquals+1, end, ';');
    if (nextSemicolon != end &&
        *(nextSemicolon + 1) != ' ')
      return std::string{}; // Malformed cookie header, no space after semicolon

    assert(nextEquals < nextSemicolon); // Should be guaranteed because nextSemicolon search starts at nextEquals+1
    assert(nextSemicolon <= end); // Should be guaranteed because nextSemicolon search ends at 'end'
    assert(start <= nextEquals); // Should be guaranteed because nextEquals search starts at start

    // othercookie=value; cookiename=cookievalue; lastCookie = value
    // ^- cookies         ^- start  ^           ^- nextSemicolon    ^- end
    //                              \- nextEquals
    // or (last cookie)
    // othercookie=value; cookiename=cookievalue
    // ^- cookies         ^- start  ^           ^- nextSemicolon = end
    //                              \- nextEquals

    if (std::distance(start, nextEquals) == (long)cookieName.size() &&
        std::equal(start, nextEquals, cookieName.c_str())) {
      const char * cookieValueStart = nextEquals+1;
      assert(cookieValueStart <= end); // Because of nextEquals == end check earlier
      // Leave out trailing whitespace
      const char * cookieValueEnd = nextSemicolon == end ? std::find_if(cookieValueStart, end, is_whitespace) : nextSemicolon;

      // Handle cookie value in double quotes
      if (*cookieValueStart == '"') {
        ++cookieValueStart;
        assert(cookieValueEnd - 1 >= cookies); // Should be guaranteed because cookieValueStart >= nextEquals + 1
        if (*(cookieValueEnd - 1) != '"')
          return std::string{}; // Malformed cookie header, unbalanced double quote
        --cookieValueEnd;
      }

      // cookiename=cookievalue;
      //            ^          ^- cookieValueEnd
      //            \- cookieValueStart
      // or (double quotes)
      // cookiename="cookievalue";
      //             ^          ^- cookieValueEnd
      //             \- cookieValueStart

      if (sessionIdLength != std::distance(cookieValueStart, cookieValueEnd))
        return std::string{}; // Session ID cookie length incorrect!
      if (!std::all_of(cookieValueStart, cookieValueEnd, is_alphanumeric))
        return std::string{}; // Session IDs should be alphanumeric!
      return std::string(cookieValueStart, sessionIdLength);
    }

    start = nextSemicolon + 2; // Skip over '; '
  }
  return std::string{};
}

#ifdef WT_THREADED
WebController::SocketNotifierMap&
WebController::socketNotifiers(WSocketNotifier::Type type)
{
  switch (type) {
  case WSocketNotifier::Type::Read:
    return socketNotifiersRead_;
  case WSocketNotifier::Type::Write:
    return socketNotifiersWrite_;
  case WSocketNotifier::Type::Exception:
  default: // to avoid return warning
    return socketNotifiersExcept_;
  }
}
#endif // WT_THREADED

void WebController::socketSelected(int descriptor, WSocketNotifier::Type type)
{
#ifdef WT_THREADED
  /*
   * Find notifier, extract session Id
   */
  std::string sessionId;
  {
    SocketNotifierMap &notifiers = socketNotifiers(type);
    
    /* read lock */
    std::shared_lock<mutex_t> lock{ notifierMutex_ };
    
    SocketNotifierMap::iterator k = notifiers.find(descriptor);
    if (k == notifiers.end()) {
      lock.unlock();
      LOG_ERROR_S(&server_, "socketSelected(): socket notifier should have been "
                  "cancelled?");

      return;
    } else {
      sessionId = k->second->sessionId();
    }
  }

  server_.post(sessionId, std::bind(&WebController::socketNotify,
                                      this, descriptor, type));
#endif // WT_THREADED
}

#ifdef WT_THREADED
void WebController::socketNotify(int descriptor, WSocketNotifier::Type type)
{
  WSocketNotifier *notifier = nullptr;
  {
    SocketNotifierMap &notifiers = socketNotifiers(type);

    /* write lock */
    std::unique_lock<mutex_t> lock{ notifierMutex_ };

    SocketNotifierMap::iterator k = notifiers.find(descriptor);
    if (k != notifiers.end()) {
      notifier = k->second;
      notifiers.erase(k);
    }
  }

  if (notifier) {
    notifier->notify();
  }
}
#endif // WT_THREADED

void WebController::addSocketNotifier(WSocketNotifier *notifier)
{
#ifdef WT_THREADED
  {
    SocketNotifierMap& notifiers = socketNotifiers(notifier->type());
    
    /* write lock */
    std::unique_lock<mutex_t> lock{ notifierMutex_ };
    
    notifiers[notifier->socket()] = notifier;
  }

  switch (notifier->type()) {
  case WSocketNotifier::Type::Read:
    socketNotifier_.addReadSocket(notifier->socket());
    break;
  case WSocketNotifier::Type::Write:
    socketNotifier_.addWriteSocket(notifier->socket());
    break;
  case WSocketNotifier::Type::Exception:
    socketNotifier_.addExceptSocket(notifier->socket());
    break;
  }
#endif // WT_THREADED
}

void WebController::removeSocketNotifier(WSocketNotifier *notifier)
{
#ifdef WT_THREADED
  switch (notifier->type()) {
  case WSocketNotifier::Type::Read:
    socketNotifier_.removeReadSocket(notifier->socket());
    break;
  case WSocketNotifier::Type::Write:
    socketNotifier_.removeWriteSocket(notifier->socket());
    break;
  case WSocketNotifier::Type::Exception:
    socketNotifier_.removeExceptSocket(notifier->socket());
    break;
  }

  SocketNotifierMap &notifiers = socketNotifiers(notifier->type());

  /* write lock */
  std::unique_lock<mutex_t> lock{ notifierMutex_ };

  SocketNotifierMap::iterator i = notifiers.find(notifier->socket());
  if (i != notifiers.end()) {
    notifiers.erase(i);
  }
#endif // WT_THREADED
}

bool WebController::requestDataReceived(WebRequest *request,
                                        std::uintmax_t current,
                                        std::uintmax_t total)
{
  if (!running_) {
    return false;
  }

#ifdef WT_THREADED
  /* read lock */
  std::shared_lock<mutex_t> lock{ uploadProgressUrlsMutex_ };
#endif // WT_THREADED

  if (uploadProgressUrls_.find(request->queryString())
      != uploadProgressUrls_.end()) {
#ifdef WT_THREADED
    lock.unlock();
#endif // WT_THREADED

    CgiParser cgi(conf_.maxRequestSize(), conf_.maxFormDataSize());

    try {
      cgi.parse(*request, CgiParser::ReadHeadersOnly);
    } catch (std::exception& e) {
      LOG_ERROR_S(&server_, "could not parse request: " << e.what());
      return false;
    }

    const std::string *wtdE = request->getParameter("wtd");
    if (!wtdE) {
      return false;
    }

    std::string sessionId = *wtdE;

    UpdateResourceProgressParams params {
      str(request->getParameter("request")),
      str(request->getParameter("resource")),
      request->postDataExceeded(),
      request->extraPathInfo().to_string(),
      current,
      total
    };
    auto event = std::make_shared<ApplicationEvent>(sessionId,
      std::bind(&WebController::updateResourceProgress,
        this, std::move(params)));

    if (handleApplicationEvent(event)) {
      return !request->postDataExceeded();
    } else {
      return false;
    }
  }

  return true;
}

void WebController::updateResourceProgress(const UpdateResourceProgressParams &params)
{
  WApplication *app = WApplication::instance();

  WResource *resource = nullptr;
  if (!params.requestParam.empty() &&
      !params.pathInfo.empty()) {
    resource = app->decodeExposedResource("/path/" + params.pathInfo);
  }

  if (!resource) {
    resource = app->decodeExposedResource(params.resourceParam);
  }

  if (resource) {
    ::int64_t dataExceeded = params.postDataExceeded;
    if (dataExceeded)
      resource->dataExceeded().emit(dataExceeded);
    else
      resource->dataReceived().emit(params.current, params.total);
  }
}

bool WebController::handleApplicationEvent(const std::shared_ptr<ApplicationEvent>& event)
{
  /*
   * This should always be run from within a virgin thread of the
   * thread-pool
   */
  assert(!WebSession::Handler::instance());

  /*
   * Find session (and guard it against deletion)
   */
  std::shared_ptr<WebSession> session;
  {
#ifdef WT_THREADED
    /* read lock */
    std::shared_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

    SessionMap::iterator i = sessions_.find(event->sessionId);
    if (i != sessions_.end() && !i->second->dead()) {
      session = i->second;
    }
  }

  if (!session) {
    if (event->fallbackFunction) {
      event->fallbackFunction();
    }
    return false;
  } else {
    session->queueEvent(event);
  }

  /*
   * Try to take the session lock now to propagate the event to the
   * application.
   */
  {
    WebSession::Handler handler(session, WebSession::Handler::LockOption::TryLock);
  }

  return true;
}

void WebController::addUploadProgressUrl(const std::string& url)
{
#ifdef WT_THREADED
  /* write lock */
  std::unique_lock<mutex_t> lock{ uploadProgressUrlsMutex_ };
#endif // WT_THREADED

  uploadProgressUrls_.insert(url.substr(url.find("?") + 1));
}

void WebController::removeUploadProgressUrl(const std::string& url)
{
#ifdef WT_THREADED
  /* write lock */
  std::unique_lock<mutex_t> lock{ uploadProgressUrlsMutex_ };
#endif // WT_THREADED

  uploadProgressUrls_.erase(url.substr(url.find("?") + 1));
}

std::string WebController::computeRedirectHash(const std::string& secret,
                                               const std::string& url)
{
  return Utils::base64Encode(Utils::md5(secret + url));
}

std::string WebController::redirectSecret(const Wt::WebRequest &request) const
{
#ifndef WT_TARGET_JAVA
  if (configuration().behindReverseProxy() ||
      configuration().isTrustedProxy(request.remoteAddr())) {
    const auto secretHeader = request.headerValue(WT_REDIRECT_SECRET_HEADER);
    if (secretHeader && secretHeader[0] != '\0') {
      return secretHeader;
    }
  }
#endif // WT_TARGET_JAVA

  return redirectSecret_;
}

void WebController::handleRequest(WebRequest *request)
{
  if (!running_) {
    request->setStatus(500);
    request->flush();
    return;
  }

  if (configuration().useScriptNonce()) {
    request->addNonce();
  }

  if (!request->entryPoint_) {
    EntryPointMatch match = getEntryPoint(request);
    request->entryPoint_ = match.entryPoint;
    request->extraStartIndex_ = match.extraStartIndex;
    if (!request->entryPoint_) {
      request->setStatus(404);
      request->flush();
      return;
    }
    request->urlParams_ = std::move(match.urlParams);
  }

  CgiParser cgi(conf_.maxRequestSize(), conf_.maxFormDataSize());

  try {
    cgi.parse(*request, conf_.needReadBodyBeforeResponse()
              ? CgiParser::ReadBodyAnyway
              : CgiParser::ReadDefault);
  } catch (std::exception& e) {
    LOG_ERROR_S(&server_, "could not parse request: " << e.what());

    request->setContentType("text/html");
    request->out()
      << "<title>Error occurred.</title>"
      << "<h2>Error occurred.</h2>"
         "Error parsing CGI request: " << e.what() << std::endl;

    request->flush(WebResponse::ResponseState::ResponseDone);
    return;
  }

  if (request->entryPoint_->type() == EntryPointType::StaticResource) {
    // Requests to WWebSocketResources need some spacial handling:
    // after the handshake is done, the socket is transferred to the
    // WWebSocketConnection for futher communication.
    if (request->isWebSocketRequest()) {
      // Retrieve the static resource
      WebSocketHandlerResource* wsResource = nullptr;
      if (request->entryPoint_->resource()) {
        wsResource = dynamic_cast<WebSocketHandlerResource*>(request->entryPoint_->resource());
      }
      if(!wsResource) {
        // No static resource found
        LOG_ERROR("handleRequest: resource '" << request->pathInfo() << "' is not a WWebSocketResource");
        request->setStatus(400);
        request->setContentType("text/html");
        request->out()
          << "<title>Error occurred.</title>"
          << "<html><body><h1>Not a websocket</h1></body></html>"
          << std::endl;
        request->flush(WebResponse::ResponseState::ResponseDone);
        return;
      } else if (!request->supportsTransferWebSocketResourceSocket()) {
        // The HTTP frontend doesn't allow WWebSocketResources
        LOG_ERROR("handleRequest: websocket resources not supported by HTTP frontend");
        request->setStatus(500);
        request->setContentType("text/html");
        request->out()
          << "<title>Error occurred.</title>"
          << "<html><body><h1>WebSocket not supported</h1></body></html>"
          << std::endl;
        request->flush(WebResponse::ResponseState::ResponseDone);
        return;
      }
      // Regular handling, perform the actual handshake.
      request->entryPoint_->resource()->handle(request, (WebResponse *)request);

      // If the handshake is successful, transfer the socket.
      if (request->status() == 101) {
        request->setTransferWebSocketResourceSocketCallBack(std::bind(&WebSocketHandlerResource::moveSocket, wsResource, std::placeholders::_1, std::placeholders::_2));
      }
    } else {
      // A regular static resource
      request->entryPoint_->resource()->handle(request, (WebResponse *)request);
    }
    return;
  }

  const std::string *requestE = request->getParameter("request");
  if (requestE && *requestE == "redirect") {
    handleRedirect(request);
    return;
  }

  std::string sessionId;

  /*
   * Get session from request.
   */
  const std::string *wtdE = request->getParameter("wtd");

  if (conf_.sessionTracking() == Configuration::CookiesURL
      && !conf_.reloadIsNewSession())
    sessionId = sessionFromCookie(request->headerValue("Cookie"),
                                  request->scriptName(),
                                  conf_.fullSessionIdLength());

  std::string multiSessionCookie;
  if (conf_.sessionTracking() == Configuration::Combined)
    multiSessionCookie = sessionFromCookie(request->headerValue("Cookie"),
                                           "ms" + request->scriptName(),
                                           conf_.sessionIdLength());

  if (sessionId.empty() && wtdE)
    sessionId = *wtdE;

  std::shared_ptr<WebSession> session;
  {
    if (!singleSessionId_.empty() && sessionId != singleSessionId_) {
      if (conf_.persistentSessions()) {
        // This may be because of a race condition in the filesystem:
        // the session file is renamed in generateNewSessionId() but
        // still a request for an old session may have arrived here
        // while this was happening.
        //
        // If it is from the old app, We should be sent a reload signal,
        // this is what will be done by a new session (which does not create
        // an application).
        //
        // If it is another request to take over the persistent session,
        // it should be handled by the persistent session. We can distinguish
        // using the type of the request
        LOG_INFO_S(&server_,
                   "persistent session requested Id: " << sessionId << ", "
                   << "persistent Id: " << singleSessionId_);

#ifdef WT_THREADED
        /* read lock */
        std::shared_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED
    
        const bool sessionsEmpty = sessions_.empty();

#ifdef WT_THREADED
        lock.unlock();
#endif // WT_THREADED

        if (sessionsEmpty || strcmp(request->requestMethod(), "GET") == 0) {
          sessionId = singleSessionId_;
        }
      } else {
        sessionId = singleSessionId_;
      }
    }

#ifdef WT_THREADED
    /* read lock */
    std::shared_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

    SessionMap::const_iterator i = sessions_.find(sessionId);
    session = (i != std::end(sessions_)) ? i->second : nullptr;

#ifdef WT_THREADED
    lock.unlock();
#endif // WT_THREADED

    Configuration::SessionTracking sessionTracking = configuration().sessionTracking();

    if (!session || session->dead() ||
        (sessionTracking == Configuration::Combined &&
         (multiSessionCookie.empty() || multiSessionCookie != session->multiSessionId()))) {
      try {
        if (sessionTracking == Configuration::Combined && session && !session->dead()) {
          if (!request->headerValue("Cookie")) {
            LOG_ERROR_S(&server_, "Valid session id: " << sessionId << ", but "
                        "no cookie received (expecting multi session cookie)");
            request->setStatus(403);
            request->flush(WebResponse::ResponseState::ResponseDone);
            return;
          }
        }

        if (request->isWebSocketRequest()) {
          LOG_INFO_S(&server_, "WebSocket request for non-existing session rejected. "
                               "This is likely because of a browser with an old session "
                               "trying to reconnect (e.g. when the server was restarted)");
          request->setStatus(403);
          request->flush(WebResponse::ResponseState::ResponseDone);
          return;
        }

        if (singleSessionId_.empty()) {
          do {
            sessionId = conf_.generateSessionId();
          } while (!conf_.registerSessionId(std::string(), sessionId));
        }

        std::string favicon = request->entryPoint_->favicon();
        if (favicon.empty()) {
          conf_.readConfigurationProperty("favicon", favicon);
        }

        session = std::make_shared<WebSession>(this, sessionId,
          request->entryPoint_->type(),
          favicon, request);

        if (sessionTracking == Configuration::Combined) {
          if (multiSessionCookie.empty()) {
            multiSessionCookie = conf_.generateSessionId();
          }
          session->setMultiSessionId(multiSessionCookie);
        }

        if (sessionTracking == Configuration::CookiesURL) {
            request->addHeader("Set-Cookie",
                appSessionCookie(request->scriptName())
                + "=" + sessionId + "; Version=1;"
                + " Path=" + session->env().deploymentPath()
                + "; httponly;" + (session->env().urlScheme() == "https" ? " secure;" : "")
                + " SameSite=Strict;");
        }

        {
#ifdef WT_THREADED
          /* write lock */
          std::unique_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

          sessions_[sessionId] = session;
          ++plainHtmlSessions_;
        }

        if (server_.dedicatedSessionProcess()) {
          server_.updateProcessSessionId(sessionId);
        }
      } catch (std::exception& e) {
        LOG_ERROR_S(&server_, "could not create new session: " << e.what());
        request->flush(WebResponse::ResponseState::ResponseDone);
        return;
      }
    }
  }

  bool handled = false;
  {
    WebSession::Handler handler(session, *request, *(WebResponse *)request);

    if (!session->dead()) {
      handled = true;
      session->handleRequest(handler);
    }
  }

  if (session->dead()) {
    removeSession(sessionId);
  }

  // release session co-ownership
  session.reset();

  if (autoExpire_) {
    expireSessions(false);
  }

  if (!handled) {
    handleRequest(request);
  }
}

void WebController::handleRedirect(Wt::WebRequest *request)
{
  const std::string *urlE = request->getParameter("url");
  const std::string *hashE = request->getParameter("hash");

  if (urlE && hashE) {
    if (*hashE != computeRedirectHash(redirectSecret(*request), *urlE))
      hashE = nullptr;
  }

  if (urlE && hashE) {
    request->setRedirect(*urlE);
  } else {
    request->setContentType("text/html");
    request->out()
            << "<title>Error occurred.</title>"
            << "<h2>Error occurred.</h2><p>Invalid redirect.</p>" << std::endl;
  }

  request->flush(WebResponse::ResponseState::ResponseDone);
}

std::unique_ptr<WApplication> WebController
::doCreateApplication(WebSession *session)
{
  const EntryPoint *ep
    = WebSession::Handler::instance()->request()->entryPoint_;

  return ep->appCallback()(session->env());
}

EntryPointMatch WebController::getEntryPoint(WebRequest *request)
{
  const std::string& scriptName = request->scriptName();
  const std::string& pathInfo = request->pathInfo();

  return conf_.matchEntryPoint(scriptName, pathInfo, true);
}

std::string
WebController::generateNewSessionId(const std::shared_ptr<WebSession>& session)
{
  std::string newSessionId;
  do {
    newSessionId = conf_.generateSessionId();
  } while (!conf_.registerSessionId(session->sessionId(), newSessionId));

#ifdef WT_THREADED
  /* write lock */
  std::unique_lock<mutex_t> lock{ mutex_ };
#endif // WT_THREADED

  sessions_[newSessionId] = session;

  SessionMap::iterator i = sessions_.find(session->sessionId());
  sessions_.erase(i);

#ifdef WT_THREADED
  lock.unlock();
#endif // WT_THREADED

  if (!singleSessionId_.empty()) {
    singleSessionId_ = newSessionId;
  }

  return newSessionId;
}

void WebController::newAjaxSession()
{
  ++ajaxSessions_;
  --plainHtmlSessions_;
}

bool WebController::limitPlainHtmlSessions()
{
  if (conf_.maxPlainSessionsRatio() > 0) {
    const int plainSessions = plainHtmlSessions_;
    const int ajaxSessions = ajaxSessions_;
    return (plainSessions + ajaxSessions > 20)
      && (plainSessions > conf_.maxPlainSessionsRatio() * (ajaxSessions + plainSessions));
  }

  return false;
}

}
