// This may look like C code, but it's really -*- C++ -*-
/*
 * Copyright (C) 2008 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#ifndef WDIALOG_H_
#define WDIALOG_H_

#include <Wt/WPopupWidget.h>
#include <Wt/WContainerWidget.h>
#include <Wt/WJavaScript.h>

namespace Wt {

class DialogCover;

/*! \brief The result of a modal dialog execution.
 */
enum class DialogCode {
  Rejected, //!< Dialog closed with reject()
  Accepted  //!< Dialog closed with accept()
};

/*! \class WDialog Wt/WDialog.h Wt/WDialog.h
 *  \brief A %WDialog shows a dialog.
 *
 * By default, the dialog is <i>modal</i>. A modal window blocks the
 * user interface, and does not allow the user to interact with any
 * other part of the user interface until the dialog is closed (this
 * is enforced at the server side, so you may rely on this behavior).
 *
 * A modal dialog can be instantiated synchronously or
 * asynchronously. A non-modal dialog can only be instantiated
 * asynchronously.
 *
 * When using a dialog asynchronously, there is no API call that waits
 * for the dialog to be closed. Then, the usage is similar to
 * instantiating any other widget. The dialog may be closed by calling
 * accept(), reject() or done() (or connecting a signal to one of
 * these methods). This will hide the dialog and emit the finished()
 * signal, which you then can listen for to process the dialog result
 * and delete the dialog. Unlike other widgets, a dialog does not need
 * to be added to a parent widget, but is hidden by default. You must
 * use the method show() or \link setHidden() setHidden(false)\endlink
 * to show the dialog.
 *
 * The synchronous use of a dialog involves a call to exec() which
 * will block (suspend the thread) until the dialog window is closed,
 * and return the dialog result. Events within dialog are handled
 * using a so-called recursive event loop. Typically, an OK button
 * will be connected to accept(), and in some cases a StandardButton::Cancel button to
 * reject(). This solution has the drawback that it is not scalable to
 * many concurrent sessions, since for every session with a recursive
 * event loop, a thread is locked until exec() returns. A thread that
 * is locked by a recursive event loop cannot be used to process
 * requests from another sessions. When all threads in the threadpool
 * are locked in recursive event loops, the server will be
 * unresponsive to requests from any other session. In practical
 * terms, this means you must not use exec(), unless your application
 * will never be used by more concurrent users than the amount of
 * threads in your threadpool (like on some intranets or
 * extranets). Using exec() is not supported from outside the regular
 * event loop (i.e. when taking a lock on a session using
 * WApplication::getUpdateLock() or by posting an event using
 * WServer::post()). \if java This functionality is only available on
 * Servlet 3.0 compatible servlet containers. \endif
 *
 * Use \link setModal() setModal(false)\endlink  to create a non-modal
 * dialog. A non-modal dialog does not block the underlying user interface:
 * the user must not first deal with the dialog before interacting with the
 * rest of the user interface.
 *
 * Contents for the dialog is defined by adding it to the contents()
 * widget.
 *
 * \if cpp
 * Usage example, using the exec() method (not recommended):
 * \code
 * Wt::WDialog dialog("Personalia");
 *
 * dialog.contents()->addWidget(std::make_unique<Wt::WText>("Enter your name: "));
 * dialog.contents()->addWidget(std::make_unique<Wt::WLineEdit>());
 * dialog.contents()->addWidget(std::make_unique<Wt::WBreak>());
 *
 * dialog.contents()->addWidget(std::make_unique<Wt::WPushButton>("Ok"));
 *
 * // these events will accept() the Dialog
 * edit.enterPressed().connect(&dialog, &Wt::WDialog::accept);
 * ok.clicked().connect(&dialog, &Wt::WDialog::accept);
 *
 * if (dialog.exec() == Wt::WDialog::Accepted)
 *   setStatus("Welcome, " + edit.text());
 * \endcode
 *
 * Usage example, using the asynchronous method (recommended):
 * \code
 * void MyClass::showDialog()
 * {
 *   dialog_ = addChild(std::make_unique<Wt::WDialog>("Personalia"));
 *
 *   dialog_->contents()->addWidget(std::make_unique<Wt::WText>("Enter your name: "));
 *   edit_ = dialog_->contents()->addWidget(std::make_unique<Wt::WLineEdit>());
 *   dialog_->contents()->addWidget(std::make_unique<Wt::WBreak>());
 *
 *   Wt::WPushButton *ok = dialog_->contents()->addWidget(std::make_unique<Wt::WPushButton>("Ok"));
 *
 *   // these events will accept() the Dialog
 *   edit_->enterPressed().connect(dialog_, &Wt::WDialog::accept);
 *   ok->clicked().connect(dialog_, &Wt::WDialog::accept);
 *
 *   dialog_->finished().connect(this, &MyClass::dialogDone);
 *   dialog_->show();
 * }
 *
 * void MyClass::dialogDone(DialogCode code)
 * {
 *   if (code == Wt::WDialog::Accepted)
 *     setStatus("Welcome, " + edit_->text());
 *   removeChild(dialog_);
 * }
 * \endcode
 * \endif
 *
 * This dialog looks like this (using the default css themes):
 *
 * <TABLE border="0" align="center"> <TR> <TD>
 * \image html WDialog-default-1.png "A simple custom dialog (default)"
 * </TD> <TD>
 * \image html WDialog-polished-1.png "A simple custom dialog (polished)"
 * </TD> </TR> </TABLE>
 *
 * \note For the dialog (or rather, the silkscreen covering the user
 *       interface below) to render properly in IE, the "html body"
 *       margin is set to 0 (if it wasn't already).
 */
class WT_API WDialog : public WPopupWidget
{
public:
  /*! \brief Typedef for enum Wt::DialogCode */
  typedef DialogCode Code;

  /*! \brief Constructs a new dialog.
   *
   * Unlike other widgets, the dialog does not require a parent
   * container since it is a top-level widget.
   */
  WDialog();

  /*! \brief Constructs a dialog with a given window title.
   *
   * Unlike other widgets, the dialog does not require a parent
   * container since it is a top-level widget.
   */
  WDialog(const WString& windowTitle);

  /*! \brief Deletes a dialog.
   */
  ~WDialog();

  /*! \brief Sets the dialog window title.
   *
   * The window title is displayed in the title bar.
   *
   * \sa setTitleBarEnabled()
   */
  void setWindowTitle(const WString& title);

  /*! \brief Returns the dialog window title.
   *
   * \sa setWindowTitle()
   */
  WString windowTitle() const;

  /*! \brief Enables or disables the title bar.
   *
   * The titlebar is enabled by default.
   */
  void setTitleBarEnabled(bool enabled);

  /*! \brief Returns whether the title bar is enabled.
   *
   * \sa setTitleBarEnabled()
   */
  bool isTitleBarEnabled() const { return !titleBar_->isHidden(); }

  /*! \brief Returns the dialog title bar container.
   *
   * The title bar contains a single text that contains the
   * caption. You may customize the title bar by for example adding
   * other content.
   */
  WContainerWidget *titleBar() const { return titleBar_; }

  /*! \brief Returns the dialog contents container.
   *
   * Content to the dialog window may be added to this container widget.
   */
  WContainerWidget *contents() const { return contents_; }

  /*! \brief Returns the dialog footer container.
   *
   * This is an optional section which is typically used for buttons.
   */
  WContainerWidget *footer() const;

  /*! \brief Executes the dialog in a recursive event loop.
   *
   * Executes the dialog synchronously. This blocks the current thread
   * of execution until one of done(DialogCode), accept() or reject()
   * is called.
   *
   * <i>Warning: using exec() does not scale to many concurrent
   * sessions, since the thread is locked until exec returns, so the
   * entire server will be unresponsive when the thread pool is
   * exhausted.</i>
   *
   * \if java
   * <i>This functionality is only available on Servlet 3.0 compatible
   * servlet containers.</i>
   * \endif
   *
   * \sa done(DialogCode r), accept(), reject()
   */
  DialogCode exec(const WAnimation& animation = WAnimation());

  /*! \brief Stops the dialog.
   *
   * Sets the dialog result, and emits the finished() signal.
   *
   * \if cpp
   * If a recursive event loop was started using the exec() method, it
   * is ended.
   * \endif
   *
   * \sa finished(), result()
   */
  virtual void done(DialogCode r);

  /*! \brief Closes the dialog, with result is Accepted.
   *
   * \sa done(DialogCode r), reject()
   */
  virtual void accept();

  /*! \brief Closes the dialog, with result is Rejected.
   *
   * \sa done(DialogCode r), accept()
   */
  virtual void reject();

  /*! \brief Lets pressing the escape key reject the dialog.
   *
   * Before %Wt 3.1.5, pressing escape automatically rejected the dialog.
   * Since 3.1.4 this behaviour is no longer the default since it may
   * interfere with other functionality in the dialog. Use this method
   * to enable this behaviour.
   *
   * \sa reject()
   */
  void rejectWhenEscapePressed(bool enable = true);

  /*! \brief %Signal emitted when the dialog is closed.
   *
   * \sa done(DialogCode r), accept(), reject()
   */
  Signal<DialogCode>& finished() { return finished_; }

  /*! \brief Returns the result that was set for this dialog.
   *
   * \sa done(DialogCode r)
   */
  DialogCode result() const { return result_; }

  /*! \brief Sets whether the dialog is modal.
   *
   * A modal dialog will block the underlying user interface. A modal dialog
   * can be shown synchronously or asynchronously. A non-modal dialog can only
   * be shown asynchronously.
   *
   * By default a dialog is modal.
   */
  void setModal(bool modal);

  /*! \brief Returns whether the dialog is modal.
   *
   * \sa setModal()
   */
  bool isModal() const { return modal_; }

  /*! \brief Adds a resize handle to the dialog.
   *
   * The resize handle is shown in the bottom right corner of the dialog,
   * and allows the user to resize the dialog (but not smaller than the
   * content allows).
   *
   * This also sets the minimum width and height to WLength::Auto to
   * use the initial width and height as minimum sizes. You may want
   * to provide other values for minimum width and height to allow the
   * dialog to be reduced in size.
   *
   * The default value is \c false.
   *
   * \sa setMinimumSize(), setMaximumSize()
   */
  void setResizable(bool resizable);

  /*! \brief Returns whether the dialog has a resize handle.
   *
   * \sa setResizable()
   */
  bool resizable() const { return resizable_; }

  /*! \brief Allows the dialog to be moved.
   *
   * The dialog can be moved by grabbing the titlebar.
   *
   * The default value is \c true.
   */
  void setMovable(bool movable);

  /*! \brief Returns whether the dialog can be moved.
   *
   * \sa setMovable()
   */
  bool movable() const { return movable_; }

  /*! \brief Adds a close button to the titlebar.
   *
   * The close button is shown in the title bar. Clicking the close button
   * will reject the dialog.
   */
  void setClosable(bool closable);

  /*! \brief Returns whether the dialog can be closed.
   */
  bool closable() const { return closeIcon_ != nullptr; }

  /*! \brief Set focus on the first widget in the dialog.
   *
   * Autofocus is enabled by default. If a widget inside of
   * this dialog already has focus, the focus will not be changed.
   */
  void setAutoFocus(bool enable){ autoFocus_ = enable;}

  virtual void setHidden(bool hidden,
                         const WAnimation& animation = WAnimation()) override;

  virtual void positionAt(const WWidget *widget,
                          Orientation orientation = Orientation::Vertical,
                          WFlags<Orientation> adjustOrientations = AllOrientations)
    override;

  /*! \brief Set the position of the widget at the mouse position
   */
  void positionAt(const Wt::WMouseEvent& ev);

  /*! \brief Raises this dialog to be the top-most dialog.
   */
  void raiseToFront();

  virtual void setMinimumSize(const WLength& width, const WLength& height)
    override;
  virtual void setMaximumSize(const WLength& width, const WLength& height)
    override;

  /*! \brief %Signal emitted when the dialog is being resized by the user.
   *
   * The information passed are the new width and height.
   *
   * \sa setResizable()
   */
  JSignal<int, int>& resized() { return resized_; }

  /*! \brief %Signal emitted when the dialog is being moved by the user.
   *
   * The information passed are the new x and y position
   * (relative to the wietdow).
   */
  JSignal<int, int>& moved() { return moved_; }

  /** @name keyboard and mouse events
   */
  //!@{
  /*! \brief Event signal emitted when a keyboard key is pushed down.
   *
   *  The event will be triggered if nothing in the WDialog has focus
   *
   *  \sa WInteractiveWidget::keyWentDown
   */
  EventSignal<WKeyEvent>& keyWentDown();

  /*! \brief Event signal emitted when a "character" was entered.
   *
   *  The event will be triggered if nothing in the WDialog has focus
   *
   *  \sa WInteractiveWidget::keyPressed
   */
  EventSignal<WKeyEvent>& keyPressed();

  /*! \brief Event signal emitted when a keyboard key is released.
   *
   *  The event will be triggered if nothing in the WDialog has focus
   *
   *  \sa WInteractiveWidget::keyWentUp
   */
  EventSignal<WKeyEvent>& keyWentUp();

  /*! \brief Event signal emitted when enter was pressed.
   *
   *  The event will be triggered if nothing in the WDialog has focus
   *
   *  \sa WInteractiveWidget::enterPressed
   */
  EventSignal<>& enterPressed();

  /*! \brief Event signal emitted when escape was pressed.
   *
   *  The event will be triggered if nothing in the WDialog has focus
   *
   *  \sa WInteractiveWidget::escapePressed
   *
   */
  EventSignal<>& escapePressed();
  //!@}

  /*! \brief Event signal emitted when a finger is placed on the screen.
   */
  EventSignal<WTouchEvent>& touchStarted();

  /*! \brief Event signal emitted when a finger is removed from the screen.
   */
  EventSignal<WTouchEvent>& touchEnded();

  /*! \brief Event signal emitted when a finger, which is already placed on the screen, is moved across the screen.
   */
  EventSignal<WTouchEvent>& touchMoved();

protected:
  virtual void render(WFlags<RenderFlag> flags) override;
  virtual void onPathChange() override;

private:
  WTemplate *impl_;
  WTemplate *caption_;
  WInteractWidget *closeIcon_;
  WContainerWidget *titleBar_;
  WContainerWidget *contents_;
  WContainerWidget *layoutContainer_;
  mutable WContainerWidget *footer_;
  bool modal_, resizable_, movable_, escapeIsReject_, autoFocus_;
  JSignal<int,int> moved_, resized_;
  JSignal<int> zIndexChanged_;
  std::vector<std::string> delayedJs_;

  Signal<DialogCode> finished_;
  DialogCode result_;
  bool recursiveEventLoop_;

  Wt::Signals::connection escapeConnection1_, escapeConnection2_,
    enterConnection1_, enterConnection2_;

  void create();
  void onEscapePressed();
  void onDefaultPressed();
  void bringToFront(const WMouseEvent &e);
  void zIndexChanged(int zIndex);

  void doJSAfterLoad(std::string js);

  DialogCover *cover();

  friend class DialogCover;
};

}

#endif // WDIALOG_H_
