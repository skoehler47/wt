/*
 * Copyright (C) 2026 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#include <boost/test/unit_test.hpp>

#include <Wt/Test/WTestEnvironment.h>
#include <Wt/WApplication.h>
#include <Wt/WMenu.h>
#include <Wt/WStackedWidget.h>
#include <Wt/WText.h>

BOOST_AUTO_TEST_CASE(WMenu_select_propagation_to_parent_and_submenus)
{
  Wt::Test::WTestEnvironment testEnv;
  Wt::WApplication app(testEnv);

  Wt::WStackedWidget *stack = app.root()->addNew<Wt::WStackedWidget>();
  Wt::WMenu *menu = app.root()->addNew<Wt::WMenu>(stack);

  Wt::WMenuItem *item0 = menu->addItem("Item 0", std::make_unique<Wt::WText>("Content 0"));

  auto subMenuPtr_ = std::make_unique<Wt::WMenu>(stack);
  Wt::WMenu* subMenu = subMenuPtr_.get();
  subMenu->addItem("Item 1.1", std::make_unique<Wt::WText>("Content 1.1"));

  auto subSubMenuPtr_ = std::make_unique<Wt::WMenu>(stack);
  Wt::WMenu* subSubMenu = subSubMenuPtr_.get();
  subSubMenu->addItem("Item 1.2.1", std::make_unique<Wt::WText>("Content 1.2.1"));
  subSubMenu->addItem("Item 1.2.2", std::make_unique<Wt::WText>("Content 1.2.2"));
  Wt::WMenuItem *item1_2_3 = subSubMenu->addItem("Item 1.2.3", std::make_unique<Wt::WText>("Content 1.2.3"));

  Wt::WMenuItem *item1_2 = subMenu->addMenu("Item 1.2", std::move(subSubMenuPtr_));
  subMenu->addItem("Item 1.3", std::make_unique<Wt::WText>("Content 1.3"));

  Wt::WMenuItem *item1 = menu->addMenu("Item 1", std::move(subMenuPtr_));
  menu->addItem("Item 2", std::make_unique<Wt::WText>("Content 2"));

  // By default, the first item of the top menu is selected.
  BOOST_TEST(menu->currentItem() == item0);
  BOOST_TEST(subMenu->currentItem() == nullptr);
  BOOST_TEST(subSubMenu->currentItem() == nullptr);
  BOOST_REQUIRE_EQUAL(menu->currentIndex(), 0);
  BOOST_REQUIRE_EQUAL(subMenu->currentIndex(), -1);
  BOOST_REQUIRE_EQUAL(subSubMenu->currentIndex(), -1);

  // Select should be propagated to the parent menus.
  subSubMenu->select(2);
  BOOST_TEST(menu->currentItem() == item1);
  BOOST_TEST(subMenu->currentItem() == item1_2);
  BOOST_TEST(subSubMenu->currentItem() == item1_2_3);
  BOOST_REQUIRE_EQUAL(menu->currentIndex(), 1);
  BOOST_REQUIRE_EQUAL(subMenu->currentIndex(), 1);
  BOOST_REQUIRE_EQUAL(subSubMenu->currentIndex(), 2);

  // Select should not be propagated to the submenus.
  menu->select(0);
  BOOST_TEST(menu->currentItem() == item0);
  BOOST_TEST(subMenu->currentItem() == item1_2);
  BOOST_TEST(subSubMenu->currentItem() == item1_2_3);
  BOOST_REQUIRE_EQUAL(menu->currentIndex(), 0);
  BOOST_REQUIRE_EQUAL(subMenu->currentIndex(), 1);
  BOOST_REQUIRE_EQUAL(subSubMenu->currentIndex(), 2);

  // Select should be propagated to the parent menu even when the index did not change.
  subSubMenu->select(2);
  BOOST_TEST(menu->currentItem() == item1);
  BOOST_TEST(subMenu->currentItem() == item1_2);
  BOOST_TEST(subSubMenu->currentItem() == item1_2_3);
  BOOST_TEST(menu->currentIndex() == 1);
  BOOST_TEST(subMenu->currentIndex() == 1);
  BOOST_TEST(subSubMenu->currentIndex() == 2);

}

BOOST_AUTO_TEST_CASE(WMenu_addItem_change_index_for_internal_path_match)
{
  Wt::Test::WTestEnvironment testEnv;
  testEnv.setInternalPath("/links");
  Wt::WApplication app(testEnv);

  Wt::WStackedWidget *stack = app.root()->addNew<Wt::WStackedWidget>();
  Wt::WMenu *menu = app.root()->addNew<Wt::WMenu>(stack);
  menu->setInternalPathEnabled("/");

  BOOST_TEST(menu->currentIndex() == -1);

  menu->addItem("dashboard", std::make_unique<Wt::WText>("Dashboard"));

  BOOST_TEST(menu->currentIndex() == 0);

  // Check that adding an item with the internal path changes the index
  menu->addItem("links", std::make_unique<Wt::WText>("Links"));

  BOOST_TEST(menu->currentIndex() == 1);

  // Check that adding an item with an empty path component does not change the index
  int previousIndex = menu->currentIndex();
  menu->addItem("", std::make_unique<Wt::WText>("Account Settings Page"));

  BOOST_TEST(menu->currentIndex() == previousIndex);
}

BOOST_AUTO_TEST_CASE(WMenu_internal_path_matching_segment_boundary)
{
  Wt::Test::WTestEnvironment testEnv;
  testEnv.setInternalPath("/contact-us");
  Wt::WApplication app(testEnv);

  Wt::WStackedWidget *stack = app.root()->addNew<Wt::WStackedWidget>();
  Wt::WMenu *menu = app.root()->addNew<Wt::WMenu>(stack);
  menu->setInternalPathEnabled("/");

  menu->addItem("dashboard", std::make_unique<Wt::WText>("Dashboard"));

  BOOST_TEST(menu->currentIndex() == 0);

  menu->addItem("contact", std::make_unique<Wt::WText>("Contact Page"));

  BOOST_TEST(menu->currentIndex() == 0);

  auto downloadItem = menu->addItem("download", std::make_unique<Wt::WText>("Download Page"));
  downloadItem->setPathComponent("download/");

  BOOST_TEST(menu->currentIndex() == 0);

  app.setInternalPath("/contact/us",  true);

  BOOST_TEST(menu->currentIndex() == 1);

  // Check that path components ending with a slash are correctly matched
  app.setInternalPath("/download/file",  true);

  BOOST_TEST(menu->currentIndex() == 2);
}

