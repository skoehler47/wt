/*
 * Copyright (C) 2026 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#include <boost/test/unit_test.hpp>

#include "Wt/Auth/Dbo/AuthInfo.h"
#include "Wt/Auth/Dbo/UserDatabase.h"

#include <Wt/Test/WTestEnvironment.h>

#include <Wt/WApplication.h>
#include <Wt/Auth/AuthService.h>
#include <Wt/Auth/AuthThrottle.h>
#include "Wt/Auth/Identity.h"
#include <Wt/Auth/Login.h>
#include <Wt/Auth/Mfa/Totp.h>
#include <Wt/Auth/Mfa/TotpProcess.h>
#include <Wt/Auth/PasswordService.h>

#include <Wt/WDate.h>
#include <Wt/WDateTime.h>
#include <Wt/WLineEdit.h>
#include <Wt/WTemplate.h>
#include <Wt/WTime.h>

#include "../dbo/DboFixture.h"

#include <chrono>
#include <thread>

using namespace Wt;

namespace {
  class TestUser;
  typedef Auth::Dbo::AuthInfo<TestUser> AuthInfo;
  typedef Wt::Dbo::collection<Wt::Dbo::ptr<TestUser>> TestUsers;

  class TestUser : public Wt::Dbo::Dbo<TestUser>
  {
  public:
    TestUser() { }

    Wt::Dbo::collection<Wt::Dbo::ptr<AuthInfo>> authInfos;

    template<class Action>
    void persist(Action& a)
    {
      Wt::Dbo::hasMany(a, authInfos, Wt::Dbo::ManyToOne, "user");
    }
  };

  typedef Auth::Dbo::UserDatabase<AuthInfo> UserDatabase;

  struct TotpProcessDboFixture : DboFixtureBase
  {
    TotpProcessDboFixture()
      : DboFixtureBase()
    {
      myAuthService_ = std::make_unique<Auth::AuthService>();

      session_->mapClass<TestUser>("user");
      session_->mapClass<AuthInfo>("auth_info");
      session_->mapClass<AuthInfo::AuthIdentityType>("auth_identity");
      session_->mapClass<AuthInfo::AuthTokenType>("auth_token");

      users_ = std::make_unique<UserDatabase>(*session_);

      try {
        Wt::Dbo::Transaction transaction(*session_);
        session_->dropTables();
      } catch (...) {
      }

      Wt::Dbo::Transaction transaction(*session_);
      session_->createTables();
      transaction.commit();

    }

    std::unique_ptr<Auth::AuthService> myAuthService_;

    std::unique_ptr<UserDatabase> users_;
  };

  class TestTotpProcess: public Auth::Mfa::TotpProcess
  {
  public:
    TestTotpProcess(const Auth::AuthService& authService, Auth::AbstractUserDatabase& users, Auth::Login& login, Dbo::Session* session)
      : Auth::Mfa::TotpProcess(authService, users, login),
        session_(session)
    { }

    void registerUser() {
      Wt::Dbo::Transaction transaction(*session_);
      auto view = createSetupView();
      WTemplate* templateView = dynamic_cast<WTemplate*>(view.get());
      WLineEdit* codeEdit = dynamic_cast<WLineEdit*>(templateView->resolveWidget("totp-code"));

      std::string secretKey = currentSecretKey();
      std::string code = Auth::Mfa::generateCode(secretKey, 6, std::chrono::seconds(WDateTime::currentDateTime().toTime_t()));
      codeEdit->setText(code);
      verifyCode(templateView, false);
    }

    void doVerifyCode(WTemplate* t, const std::string& code) {
      WLineEdit* codeEdit = dynamic_cast<WLineEdit*>(t->resolveWidget("totp-code"));
      codeEdit->setText(code);
      verifyCode(t, true);
    }

    int throttlingDelay() const {
      return throttlingDelay_;
    }

    int delayForNextAttempt() const {
      return mfaThrottle()->delayForNextAttempt(login().user());
    }

  private:
    Dbo::Session* session_;
  };
}

BOOST_AUTO_TEST_CASE( mfa_throttle_enabled_failure_test )
{
  Wt::Test::WTestEnvironment testEnv;
  Wt::WApplication app(testEnv);
  TotpProcessDboFixture f;

  Wt::Dbo::Transaction transaction(*f.session_);
  Auth::User user = f.users_->registerNew();
  transaction.commit();

  {
    Auth::Login login;
    login.login(user, Auth::LoginState::RequiresMfa);

    TestTotpProcess totpProcess(*(f.myAuthService_.get()), *(f.users_.get()), login, f.session_);
    totpProcess.registerUser();
    login.logout();
  }
  transaction.commit();


  Auth::Login login;
  login.login(user, Auth::LoginState::RequiresMfa);
  TestTotpProcess totpProcess(*(f.myAuthService_.get()), *(f.users_.get()), login, f.session_);
  totpProcess.setMfaThrottle(std::make_unique<Wt::Auth::AuthThrottle>());

  auto view = totpProcess.createInputView();
  WTemplate* templateView = dynamic_cast<WTemplate*>(view.get());

  std::vector<int> attemptResults { 1, 5, 10, 25, 25};

  int delay = 0;

  // Test for 5 failure attempts
  for (std::size_t failures = 0; failures < 5; ++failures) {
    // wait for the delay to pass, so that the next attempt can be made
    std::this_thread::sleep_for(std::chrono::seconds(delay));

    auto start = std::chrono::system_clock::now();
    // Have one additional login failure
    totpProcess.doVerifyCode(templateView, "00000");

    auto end = std::chrono::system_clock::now();
    delay = totpProcess.throttlingDelay(); // delay showed in the view.
    int elapsed = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(end - start).count());
    elapsed++; // Add 1 second because it was rounded down

    BOOST_REQUIRE(attemptResults[failures] - elapsed <= delay);
    BOOST_REQUIRE(delay <= attemptResults[failures]);
    transaction.commit();
  }
}

BOOST_AUTO_TEST_CASE( mfa_throttle_ignore_attempt_during_cooldown )
{
  Wt::Test::WTestEnvironment testEnv;
  Wt::WApplication app(testEnv);
  TotpProcessDboFixture f;

  Wt::Dbo::Transaction transaction(*f.session_);
  Auth::User user = f.users_->registerNew();
  transaction.commit();

  {
    Auth::Login login;
    login.login(user, Auth::LoginState::RequiresMfa);

    TestTotpProcess totpProcess(*(f.myAuthService_.get()), *(f.users_.get()), login, f.session_);
    totpProcess.registerUser();
    login.logout();
  }
  transaction.commit();


  Auth::Login login;
  login.login(user, Auth::LoginState::RequiresMfa);
  TestTotpProcess totpProcess(*(f.myAuthService_.get()), *(f.users_.get()), login, f.session_);
  totpProcess.setMfaThrottle(std::make_unique<Wt::Auth::AuthThrottle>());

  auto view = totpProcess.createInputView();
  WTemplate* templateView = dynamic_cast<WTemplate*>(view.get());

  std::vector<int> attemptResults { 1, 5, 10 };

  BOOST_REQUIRE(user.failedLoginAttempts() == 0);

  f.users_->setFailedLoginAttempts(user, 1);
  f.users_->setLastLoginAttempt(user, WDateTime::currentDateTime().addSecs(-1));
  transaction.commit();

  BOOST_REQUIRE(user.failedLoginAttempts() == 1);

  auto start = std::chrono::system_clock::now();
  // the second attempt of the loop should be ignored.
  for (std::size_t failures = 0; failures < 2; ++failures) {
    totpProcess.doVerifyCode(templateView, "00000");
    transaction.commit();
  }

  int delay = totpProcess.delayForNextAttempt();
  auto end = std::chrono::system_clock::now();
  int elapsed = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(end - start).count());
  elapsed++; // Add 1 second because it was rounded down

  BOOST_TEST(user.failedLoginAttempts() == 2);
  BOOST_TEST(attemptResults[1] - elapsed <= delay);
  BOOST_TEST(delay <= attemptResults[1]);
}

