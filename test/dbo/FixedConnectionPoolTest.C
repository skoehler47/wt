/*
 * Copyright (C) 2020 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#include <boost/test/unit_test.hpp>

#include <Wt/Dbo/Dbo.h>

#include "DboFixture.h"

#include <algorithm>
#include <thread>
#include <future>
#include <vector>

namespace dbo = Wt::Dbo;

namespace {
  class DummyConnection : public dbo::SqlConnection
  {
  public:
    DummyConnection() = default;
    virtual std::unique_ptr<SqlConnection> clone() const override
    {
      return std::make_unique<DummyConnection>();
    }

    virtual void startTransaction() override {}
    virtual void commitTransaction() override {}
    virtual void rollbackTransaction() override {}

    virtual std::unique_ptr<dbo::SqlStatement>
    prepareStatement(const std::string& /*sql*/) override
    {
      return std::unique_ptr<dbo::SqlStatement>();
    }

    virtual std::string autoincrementSql() const override { return {}; }
    virtual std::vector<std::string>
    autoincrementCreateSequenceSql(const std::string& /*table*/,
                                   const std::string& /*id*/) const override
    { return {}; }
    virtual std::vector<std::string>
    autoincrementDropSequenceSql(const std::string& /*table*/,
                                 const std::string& /*id*/) const override
    { return {}; }
    virtual std::string autoincrementType() const override { return "bigint"; }
    virtual std::string autoincrementInsertSuffix(const std::string& /*id*/) const override { return {}; }

    virtual const char *dateTimeType(dbo::SqlDateTimeType /*type*/) const override { return "timestamp"; }
    virtual const char *blobType() const override { return "blob"; }
  };
}

#ifdef WT_THREADED
BOOST_AUTO_TEST_CASE( FixedConnectionPool_successive_returnConnection_wakes_up_waiting_threads )
{
  dbo::FixedSqlConnectionPool pool(std::make_unique<DummyConnection>(), 5);

  auto con1 = pool.getConnection();
  auto con2 = pool.getConnection();
  auto con3 = pool.getConnection();
  auto con4 = pool.getConnection();
  auto con5 = pool.getConnection();

  // all connections of pool are now used.

  std::promise<void> t1Ready, t2Ready, t1Done, t2Done;
  auto thread1Ready = t1Ready.get_future();
  auto thread2Ready = t2Ready.get_future();
  auto thread1Done = t1Done.get_future();
  auto thread2Done = t2Done.get_future();

  auto thread1 = std::thread([&pool, &t1Ready, &t1Done]() {
    try { t1Ready.set_value(); } catch(...) {}
    pool.getConnection();
    try { t1Done.set_value(); } catch(...) {}
  });

  auto thread2 = std::thread([&pool, &t2Ready, &t2Done]() {
    try { t2Ready.set_value(); } catch(...) {}
    pool.getConnection();
    try { t2Done.set_value(); } catch(...) {}
  });

  constexpr auto timeout = std::chrono::seconds(5);
  // wait for threads to be waiting for a connection
  BOOST_REQUIRE(thread1Ready.wait_for(timeout) == std::future_status::ready);
  BOOST_REQUIRE(thread2Ready.wait_for(timeout) == std::future_status::ready);

  // release two connections immediately after each other
  pool.returnConnection(std::move(con1));
  pool.returnConnection(std::move(con2));
  pool.returnConnection(std::move(con3));
  pool.returnConnection(std::move(con4));
  pool.returnConnection(std::move(con5));

  // wait for threads to obtain a connection (ensure no deadlock)
  BOOST_REQUIRE(thread1Done.wait_for(timeout) == std::future_status::ready);
  BOOST_REQUIRE(thread2Done.wait_for(timeout) == std::future_status::ready);

  if (thread1.joinable()) {
    thread1.join();
  }
  if (thread2.joinable()) {
    thread2.join();
  }
}
#endif // WT_THREADED
