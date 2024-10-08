// This may look like C code, but it's really -*- C++ -*-
/*
 * Copyright (C) 2011 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#ifndef WT_AUTH_AUTH_WIDGET_H_
#define WT_AUTH_AUTH_WIDGET_H_

#include <Wt/Auth/AuthModel.h>
#include <Wt/Auth/OAuthService.h>
#include <Wt/Auth/RegistrationModel.h>

#include <Wt/WDialog.h>
#include <Wt/WMessageBox.h>
#include <Wt/WTemplateFormView.h>

namespace Wt {
  namespace Auth {

    namespace Mfa {
      class AbstractMfaProcess;
    }

class AbstractUserDatabase;
class AuthModel;
class Login;
class User;

/*! \class AuthWidget Wt/Auth/AuthWidget.h
 *  \brief An authentication widget.
 *
 * The authentication widget is a widget that provides a login or
 * logout function (depending on whether the user is currently logged
 * in). You can use it for either or both purposes.
 *
 * Login or logout events are signalled to a Login object on which
 * this widget acts.
 *
 * The widget also processes environmental information related to
 * authentication:
 *
 * - email tokens, which are indicated in an internal path. The widget
 *   uses dialogs (by default) to interact with the user to act on the token.
 * - authentication tokens, which are stored in browser cookies, to implement
 *   remember-me functionality.
 *
 * The processEnvironment() method initiates this process, and should
 * typically be called only at application startup time.
 *
 * The authentication widget is implemented as a View for an
 * AuthModel, which can be set using setModel(). The login logic (at
 * this moment only for password-based authentication) is handled by
 * this model.
 *
 * It is very likely that the off-the shelf authentication widget does
 * not satisfy entirely to your taste or functional requirements. The
 * widget uses three methods to allow customization:
 *
 * - as a WTemplateFormView, you may change the layout and styling of
 *   to your liking.
 * - the authentication logic is delegated to an AuthModel and can
 *   can be specialized or can be used with a custom view altogether.
 * - the views are created using virtual methods, which may be specialized
 *   to create a customized view or to apply changes to the default view.
 *
 * \ingroup auth
 */
class WT_API AuthWidget : public WTemplateFormView
{
public:
  /*! \brief Constructor
   *
   * Creates a new authentication widget. This creates an AuthModel
   * using the given authentication service \p baseAuth and user
   * database \p users.
   *
   * The result of authentication changes is propagated to the rest of
   * the application using a \p login object.
   *
   * Authentication services need to be configured in the model().
   */
  AuthWidget(const AuthService& baseAuth, AbstractUserDatabase& users,
             Login& login);

  /*! \brief Constructor.
   *
   * Creates a new authentication widget.
   *
   * The result of authentication changes is propagated to the rest of
   * the application using a \p login object.
   *
   * You need to call setModel() to configure a model for this view.
   */
  AuthWidget(Login& login);

  ~AuthWidget();

  /*! \brief Sets a model.
   *
   * This sets a model to be used for authentication.
   */
  void setModel(std::unique_ptr<AuthModel> model);

  /*! \brief Returns the model.
   *
   * The model is used only for the login function.
   *
   * \sa setModel()
   */
  AuthModel *model() const { return model_.get(); }

  /*! \brief Returns the login object.
   *
   * This login object is used to keep track of the user currently
   * authenticated.
   */
  Login& login() { return login_; }

  /*! \brief Sets an internal path for authentication services.
   *
   * Only the registration function is made available through an
   * internal path (so that one can redirect a user to the
   * registration page). Other internal paths involved in
   * authentication are configured in the service classes:
   * - AuthService::setEmailRedirectInternalPath(): email tokens
   * - OAuthService::redirectInternalPath(): an internal path used during
   *   the oauth process.
   */
  void setInternalBasePath(const std::string& path);

  /*! \brief Returns the internal path.
   *
   * \sa setInternalBasePath()
   */
  std::string internalBasePath() const { return basePath_; }

  /*! \brief Configures registration capabilities.
   *
   * Although the AuthWidget itself does not implement a registration
   * view, it may offer a button/link to do so, and calls
   * registerNewUser() when a user wishes to register.
   *
   * Even if registration is not enabled, the result of an
   * OAuthService login process may be that a new user is
   * identified. Then the createRegistrationView() is also used to
   * present this new user with a registration view, passing the
   * information obtained through OAuth.
   */
  void setRegistrationEnabled(bool enabled);

  /*! \brief Starts a new registration process.
   *
   * This calls \p registerNewUser(0).
   */
  void registerNewUser();

  /*! \brief Starts a new registration process.
   *
   * This starts a new registration process, and may be called in
   * response to a user action, an internal path change, or an
   * OAuthService login procedure which identified a new user. In the
   * latter case, the OAuth-provided information is passed as
   * parameter \p oauth.
   *
   * The default implementation creates a view using
   * createRegistrationView(), and shows it in a dialog using
   * showDialog().
   */
  virtual void registerNewUser(const Identity& oauth);

  /*! \brief Processes the (initial) environment.
   *
   * This method process environmental information that may be
   * relevant to authentication:
   *
   * - email tokens, which are indicated through an internal path. The
   *   widget uses dialogs (by default) to interact with the user to
   *   act on the token.
   *
   * - authentication tokens, which are stored in browser cookies, to
   *   implement remember-me functionality. When logging in using an
   *   authentication token, the login is considered "weak" (since a
   *   user may have inadvertently forgotten to logout from a public
   *   computer). You should let the user authenticate using another,
   *   primary method before doing sensitive operations. The
   *   createPasswordPromptDialog() method may be useful for this.
  *    This token denotes a regular username/password login. If the
  *    "remember-me" functionality is enabled for it, and selected, a
  *    token will be produced, named according to
  *    AuthService::authTokenCookieName(), and valid for
  *    AuthService::authTokenValidity() (in minutes). Both can be set by
  *    enabling authentication tokens with
  *    AuthService::setAuthTokenaEnabled(). By default the cookie will be
  *    called "wtauth" and will be valid for two weeks.
   *
   * \sa letUpdatePassword()
   */
  virtual void processEnvironment();

  /*! \brief Lets the user update his password.
   *
   * This creates a view to let the user enter his new password.
   *
   * The default implementation creates a new view using
   * createUpdatePasswordView() and shows it in a dialog using
   * showDialog().
   */
  virtual void letUpdatePassword(const User& user, bool promptPassword);

  /*! \brief Lets the user "recover" a lost password.
   *
   * This creates a view to let the user enter his email address, used
   * to send an email containing instructions to enter a new password.
   *
   * The default implementation creates a new view using
   * createLostPasswordView() and shows it in a dialog using
   * showDialog().
   */
  virtual void handleLostPassword();

  /*! \brief Creates a lost password view.
   *
   * When email verification has been enabled, the user may indicate
   * that he has lost his password -- then proof of controlling the same
   * email address that had associated with his account is sufficient to
   * allow him to enter a new password.
   *
   * This creates the widget used to let the user enter his email
   * address. The default implementation creates a new
   * LostPasswordWidget.
   *
   * \sa handleLostPassword()
   */
  virtual std::unique_ptr<WWidget> createLostPasswordView();

  /*! \brief Creates a registration view.
   *
   * This creates a registration view, optionally using information
   * already obtained from a third party identification service (such as
   * an OAuth provider).
   *
   * The default implementation creates a new RegistrationWidget
   * with a model created using createRegistrationModel().
   *
   * \sa registerNewUser()
   */
  virtual std::unique_ptr<WWidget> createRegistrationView(const Identity& id);

  /*! \brief Lets the user resend the verification email.
   *
   * This creates a view to let the user resend the email to verify
   * their email address.
   *
   * The default implementation creates a new view using
   * createResendEmailVerificationView() and shows it in a dialog using
   * showDialog().
   */
  virtual void letResendEmailVerification();

  /*! \brief Creates a view to resend the email verification email.
   *
   * If AuthService::emailVerificationRequired() is \c true, a button will be
   * shown next to the user name field to resend the verification email
   * (if the email was not yet verified). This button will show a dialog
   * containing the widget returned by this method. The default implementation
   * instantiates a ResendEmailVerificationWidget.
   *
   * This creates the widget used to let the user chose a new
   * password. The default implementation instantiates an
   * UpdatePasswordWidget.
   *
   * Note that if email verification is optional, the application should
   * provide its own mechanism to resend the verification email (e.g. in
   * a user settings widget).
   */
  virtual std::unique_ptr<WWidget> createResendEmailVerificationView();

  /*! \brief Creates a view to update a user's password.
   *
   * If \p promptPassword is \c true, the user has to enter his current
   * password in addition to a new password.
   *
   * This creates the widget used to let the user chose a new
   * password. The default implementation instantiates an
   * UpdatePasswordWidget.
   *
   * \sa letUpdatePassword()
   */
  virtual std::unique_ptr<WWidget>
    createUpdatePasswordView(const User& user, bool promptPassword);

  /*! \brief Creates a password prompt dialog.
   *
   * This creates a dialog
   * password. The user is taken from the \p login object, which also
   * signals an eventual success using its Login::changed() signal.
   *
   * The default implementation instantiates a PasswordPromptDialog.
   */
  virtual std::unique_ptr<WDialog> createPasswordPromptDialog(Login& login);

  /*! \brief Create the MFA process.
   *
   * When MFA is enabled (AuthService::setMfaProvider() is set), this will
   * be called to create a specific MFA process. This can be used by
   * developers to provide their own implementation, and ensure that the
   * right widgets are shown to the user.
   *
   * By default this will generate a Mfa::TotpProcess.
   */
  virtual std::unique_ptr<Mfa::AbstractMfaProcess> createMfaProcess();

  /*! \brief Shows the MFA process in the UI.
   *
   * This functionality manages how the MFA step is shown to the user.
   * Developers can override this to show the step in any way they see
   * fit. This can be shown as part of the main view, as a pop-up, ...
   *
   * It will also need to decide whether the setup view
   * (Mfa::AbstractMfaProcess::createSetupView()) or input view
   * (Mfa::AbstractMfaProcess::createInputView()) is shown to the user.
   *
   * By default this will show the process in the main view, replacing the
   * normal login widget with the right view on the MFA process.
   */
  virtual void createMfaView();

  void attemptPasswordLogin();

  /*! \brief Displays the error message.
   *
   * This method display an dialog showing the error
   */
  virtual void displayError(const WString& error);

  /*! \brief Displays the info message.
   *
   * This method display an dialog showing the info
   */
  virtual void displayInfo(const WString& message);

protected:
  /*! \brief Creates the user-interface.
   *
   * This method is called just before an initial rendering, and creates
   * the initial view.
   *
   * The default implementation calls createLoginView() or
   * createLoggedInView() depending on whether a user is currently
   * logged in.
   *
   * If MFA is enabled (AuthService::mfaEnabled()), this may call
   * createMfaView(). This will be called if the user that is logging in
   * has this step enabled (AuthModel::hasMfaStep()).
   */
  virtual void create();

  /*! \brief Creates the login view.
   *
   * This creates a view that allows the user to login, and is shown when
   * no user is current logged in.
   *
   * The default implementation renders the
   * <tt>"Wt.Auth.template.login"</tt> template, and binds fields
   * using createPasswordLoginView() and createOAuthLoginView().
   */
  virtual void createLoginView();

  /*! \brief Creates the view shown when the user is logged in.
   *
   * The default implementation renders the
   * <tt>"Wt.Auth.template.logged-in"</tt> template.
   */
  virtual void createLoggedInView();

  /*! \brief Creates a password login view.
   *
   * This is used by the default implementation of createLoginView()
   * to prompt for the information needed for logging in using a
   * username and password. The default implementation implements a view
   * guided by the model().
   *
   * \sa createLoginView()
   */
  virtual void createPasswordLoginView();

  /*! \brief Creates a widget to login using OAuth.
   *
   * The default implementation adds an icon for each OAuth service
   * provider available. The icon that will be used for each service
   * is a PNG file with a path based on the
   * \link OAuthService::name name \endlink of the service. If the
   * name is is "myService", then the icon path will be "css/oauth-myService.png".
   * Wt does not bundle any icons by default, so you should make sure that
   * the icon is in place.
   *
   * There's a lot to say about making a usable login mechanism for
   * OAuth (and federated login services in general), see
   * https://sites.google.com/site/oauthgoog/UXFedLogin.
   *
   * \sa createLoginView()
   */
  virtual void createOAuthLoginView();

#ifdef WT_HAS_SAML
  /*! \brief Creates a widget to login using SAML.
   *
   * The default implementation adds an icon for each SAML service
   * provider available. The icon that will be used for each service
   * is a PNG file with a path based on the
   * \link Saml::Service::name name \endlink of the service. If the
   * name is "myService", then the icon path will be "css/saml-myService.png".
   * Wt does not bundle any icons by default, so you should make sure that
   * the icon is in place.
   *
   * \sa createLoginView()
   */
  virtual void createSamlLoginView();
#endif // WT_HAS_SAML

  /*! \brief Shows a dialog.
   *
   * This shows a dialog. The default method creates a standard WDialog,
   * with the given \p title and \p contents as central widget.
   *
   * When the central widget is deleted, it deletes the dialog.
   */
  virtual WDialog *showDialog(const WString& title,
                              std::unique_ptr<WWidget> contents);

  /*! \brief Creates a registration model.
   *
   * This method creates a registration model. The default
   * implementation creates a RegistrationModel() but you may want to
   * reimplement this function to return a specialized registration
   * model (complementing a specialized registration view).
   *
   * \sa registerNewUser()
   */
  virtual std::unique_ptr<RegistrationModel> createRegistrationModel();

  virtual std::unique_ptr<WWidget> createFormWidget(AuthModel::Field field)
    override;

  virtual void render(WFlags<RenderFlag> flags) override;

private:
  std::shared_ptr<AuthModel> model_;
  std::unique_ptr<RegistrationModel> registrationModel_;
  Login& login_;
  std::string basePath_;
  bool registrationEnabled_;

  bool created_;
  std::unique_ptr<WDialog> dialog_;
  std::unique_ptr<WMessageBox> messageBox_;
  std::unique_ptr<Mfa::AbstractMfaProcess> mfaWidget_;

  void init();
  void logout();
  void loginThrottle(int delay);
  void closeDialog();
  void onLoginChange();
  void onPathChange(const std::string& path);
  bool handleRegistrationPath(const std::string& path);

  void oAuthStateChange(OAuthProcess *process);
  void oAuthDone(OAuthProcess *process, const Identity& identity);
#ifdef WT_HAS_SAML
  void samlDone(Saml::Process *process, const Identity& identity);
#endif // WT_HAS_SAML
  void updatePasswordLoginView();
};

  }
}

#endif // WT_AUTH_AUTH_WIDGET_H_
