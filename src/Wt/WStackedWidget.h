// This may look like C code, but it's really -*- C++ -*-
/*
 * Copyright (C) 2008 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#ifndef WSTACKEDWIDGET_H_
#define WSTACKEDWIDGET_H_

#include <Wt/WContainerWidget.h>

namespace Wt {

/*! \class WStackedWidget Wt/WStackedWidget.h Wt/WStackedWidget.h
 *  \brief A container widget that stacks its widgets on top of each
 *         other.
 *
 * This is a container widget which at all times has only one item
 * visible. The widget accomplishes this using setHidden(bool) on the
 * children.
 *
 * Using currentIndex() and setCurrentIndex(int index) you can
 * retrieve or set the visible widget.
 * 
 * When calling the above `setCurrentIndex(int index)`, this will fire
 * the currentWidgetChanged() signal. This allows developers to know
 * when the current visible widget has changed and what the new visible
 * widget is.
 *
 * %WStackedWidget, like WContainerWidget, is by default not inline.
 *
 * <h3>CSS</h3>
 *
 * The widget is rendered using an HTML <tt>&lt;div&gt;</tt> tag and
 * does not provide styling. It can be styled using inline or external
 * CSS as appropriate.
 *
 * \sa WMenu
 */
class WT_API WStackedWidget : public WContainerWidget
{
public:
  /*! \brief Creates a new stack.
   */
  WStackedWidget();

  virtual void addWidget(std::unique_ptr<WWidget> widget) override;

  template <typename Widget>
    Widget *addWidget(std::unique_ptr<Widget> widget)
#ifndef WT_TARGET_JAVA
  {
    Widget *result = widget.get();
    addWidget(std::unique_ptr<WWidget>(std::move(widget)));
    return result;
  }
#else // WT_TARGET_JAVA
  ;
#endif // WT_TARGET_JAVA

  using WWidget::removeWidget;

  virtual std::unique_ptr<WWidget> removeWidget(WWidget* widget) override;

  /*! \brief Returns the index of the widget that is currently shown.
   *
   * \sa setCurrentIndex(), currentWidget()
   */
  int currentIndex() const;

  /*! \brief Returns the widget that is currently shown.
   *
   * \sa setCurrentWidget(), currentIndex()
   */
  WWidget *currentWidget() const;

  /*! \brief Insert a widget at a given index
   */
  virtual void insertWidget(int index, std::unique_ptr<WWidget> widget)
    override;

  /*! \brief Changes the current widget.
   *
   * The widget with index \p index is made visible, while all other
   * widgets are hidden.
   *
   * The change of current widget is done using the animation settings
   * specified by setTransitionAnimation().
   *
   * The default value for current index is 0 if there are child widgets,
   * if no child widgets were added this returns -1.
   *
   * \sa currentIndex(), setCurrentWidget()
   */
  void setCurrentIndex(int index);

  /*! \brief Changes the current widget using a custom animation.
   *
   * \sa currentIndex(), setCurrentWidget()
   */
  void setCurrentIndex(int index, const WAnimation& animation,
                       bool autoReverse = true);

  /*! \brief Changes the current widget.
   *
   * The widget \p widget, which must have been added before, is
   * made visible, while all other widgets are hidden.
   *
   * \sa currentWidget(), setCurrentIndex()
   */
  void setCurrentWidget(WWidget *widget);

  /*! \brief Specifies an animation used during transitions.
   *
   * The animation is used to hide the previously current widget and
   * show the next current widget using setCurrentIndex().
   *
   * The initial value for \p animation is WAnimation(), specifying
   * no animation.
   *
   * When \p autoReverse is set to \c true, then the reverse animation
   * is chosen when the new index precedes the current index. This
   * only applies to AnimationEffect::SlideInFromLeft,
   * AnimationEffect::SlideInFromRight, AnimationEffect::SlideInFromTop or
   * AnimationEffect::SlideInFromBottom transition effects.
   *
   * \note If you intend to use a transition animation with a WStackedWidget
   * you should set it before it is first rendered. Otherwise, transition
   * animations caused by setCurrentIndex() may not be correctly performed.
   * If you do want to force this change you can use WApplication::processEvents
   * before calling setCurrentIndex().
   *
   * \note It is also not supported to use a AnimationEffect::Pop animation on a WStackedWidget.
   *
   *
   *
   * \sa setCurrentIndex()
   */
  void setTransitionAnimation(const WAnimation& animation,
                              bool autoReverse = false);
  
  /*! \brief %Signal which indicates that the current widget was changed.
   *
   * This signal is emitted when the current widget was changed. It holds
   * a pointer to the new current widget. It is emitted every time the 
   * setCurrentIndex() or setCurrentWidget() is called.
   */
  Signal<WWidget*>& currentWidgetChanged() {return currentWidgetChanged_;}

protected:
  virtual DomElement *createDomElement(WApplication *app) override;
  virtual void getDomChanges(std::vector<DomElement *>& result,
                             WApplication *app) override;
  virtual void render(WFlags<RenderFlag> flags) override;

private:
  WAnimation animation_;
  bool autoReverseAnimation_;
  int currentIndex_;
  bool widgetsAdded_, javaScriptDefined_, loadAnimateJS_;
  std::vector<ContentLoading> loadPolicies_;

  Signal<WWidget*> currentWidgetChanged_;
  bool hasEmittedChanged_;

  void defineJavaScript();
  void loadAnimateJS();
  void setLoadPolicy(int index, ContentLoading loadPolicy);


  friend class WMenu;
};

}

#endif // WSTACKEDWIDGET_H_
