/*
 * Copyright (C) 2026 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#include <boost/test/unit_test.hpp>

#include <Wt/Test/WTestEnvironment.h>
#include <Wt/WApplication.h>
#include <Wt/WLength.h>
#include <Wt/WPoint.h>
#include <Wt/WPopupMenu.h>
#include <Wt/WPushButton.h>

// redmine #14716: after popping up at a WPoint, popping up relative to a
// widget must not leave the off-screen offsets that popup(const WPoint&) sets.
BOOST_AUTO_TEST_CASE(WPopupMenu_popup_at_widget_clears_point_offsets)
{
  Wt::Test::WTestEnvironment testEnv;
  Wt::WApplication app(testEnv);

  auto popupPtr = std::make_unique<Wt::WPopupMenu>();
  Wt::WPopupMenu *popup = popupPtr.get();
  popup->addItem("Item 1");
  popup->addItem("Item 2");

  Wt::WPushButton *button = app.root()->addNew<Wt::WPushButton>("Button");
  button->setMenu(std::move(popupPtr));

  // popup(const WPoint&) moves the menu far off-screen; the client-side code
  // positions it afterwards.
  popup->popup(Wt::WPoint(140, 50));
  BOOST_TEST(!popup->offset(Wt::Side::Left).isAuto());
  BOOST_TEST(!popup->offset(Wt::Side::Top).isAuto());
  BOOST_TEST(popup->offset(Wt::Side::Left).value() == -10000);
  BOOST_TEST(popup->offset(Wt::Side::Top).value() == -10000);

  // Popping up relative to a widget must clear those offsets, otherwise the
  // anchor-based positioning would keep the menu off-screen.
  popup->popup(button);
  BOOST_TEST(popup->offset(Wt::Side::Left).isAuto());
  BOOST_TEST(popup->offset(Wt::Side::Top).isAuto());
}
