/*
 * Copyright (C) 2008 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include <climits>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <ostream>
#include <type_traits>

#include "WStringStream.h"

#ifndef WT_DBO_STRINGSTREAM
#include <Wt/AsioWrapper/asio.hpp>
#endif // WT_DBO_STRINGSTREAM

namespace Wt {

#ifdef WT_DBO_STRINGSTREAM
  namespace Dbo {
#endif

    WStringStream::BufferBase::BufferBase(char* buf, size_t capacity, size_t size)
      : first_(buf),
      last_(buf + capacity),
      curr_(buf + size)
    {
      /* empty */
    }

    WStringStream::BufferBase::~BufferBase()
    {
      // custom destruction order for chained buffers; standard
      // destruction order recursively destroys the unique_ptrs 
      // owning the buffers which leads to a stack overflow if
      // enough buffers are chained.
      while (next_) {
        auto tmp = std::move(next_->next_);
        next_ = std::move(tmp);
      }
    }

    const char* WStringStream::BufferBase::buf() const
    {
      return first_;
    }

    size_t WStringStream::BufferBase::capacity() const
    {
      return last_ - first_;
    }

    size_t WStringStream::BufferBase::size() const
    {
      return curr_ - first_;
    }

    size_t WStringStream::BufferBase::remaining() const
    {
      return last_ - curr_;
    }

    auto WStringStream::BufferBase::setNext(std::unique_ptr<BufferBase> next)
      -> BufferBase*
    {
      next_ = std::move(next);
      return next_.get();
    }

    auto WStringStream::BufferBase::next() const
      -> BufferBase*
    {
      return next_.get();
    }

    bool WStringStream::BufferBase::try_append(char c)
    {
      if (curr_ != last_) {
        append(c);
        return true;
      }

      return false;
    }

    bool WStringStream::BufferBase::try_append(const char* c, size_t n)
    {
      if (curr_ + n < last_) {
        append(c, n);
        return true;
      }

      return false;
    }

    void WStringStream::BufferBase::append(char c)
    {
      *curr_++ = c;
    }

    void WStringStream::BufferBase::append(const char* c, size_t n)
    {
      std::memcpy(curr_, c, n);
      curr_ += n;
    }

    bool WStringStream::BufferBase::empty() const
    {
      return first_ == curr_;
    }

    void WStringStream::BufferBase::clear()
    {
      curr_ = first_;
    }


    struct WStringStream::DynamicBuffer final
      : BufferBase
    {
      DynamicBuffer(size_t size)
        : DynamicBuffer(size, std::unique_ptr<char[]>(new char[size]))
        // note: no make_unique here since it would default initialize 
        // the allocated array, e.g. by calling memset, which is 
        // unnecessary and wastes lots of performance
      {
        /* delegated */
      }

      ~DynamicBuffer() override = default;

    private:

      DynamicBuffer(size_t size, std::unique_ptr<char[]> buf)
        : BufferBase(buf.get(), size, 0),
        buf_internal_(std::move(buf))
      {

        /* empty */
      }

      std::unique_ptr<char[]> buf_internal_;
    };


    WStringStream::WStringStream()
      : buf_(&buf_static_),
      sink_(nullptr)
    {
      /* empty */
    }

    WStringStream::WStringStream(std::ostream& sink)
      : buf_(&buf_static_),
      sink_(&sink)
    {
      /* empty */
    }

    WStringStream::WStringStream(const WStringStream& rhs)
      : buf_(&buf_static_),
      sink_(rhs.sink_)
    {
      *this << rhs;
    }

    WStringStream::WStringStream(WStringStream&& rhs) noexcept
      : buf_static_(std::move(rhs.buf_static_)),
      buf_(&buf_static_),
      sink_(rhs.sink_)
    {
      /* empty */
    }

    WStringStream::~WStringStream()
    {
      if (sink_) {
        flushSink();
      }
    }

    WStringStream& WStringStream::operator= (const WStringStream& rhs)
    {
      clear();
      sink_ = rhs.sink_;
      return *this << rhs;
    }

    WStringStream& WStringStream::operator= (WStringStream&& rhs) noexcept
    {
      buf_static_ = std::move(rhs.buf_static_);
      sink_ = rhs.sink_;
      return *this;
    }

    void WStringStream::clear()
    {
      buf_static_.clear();
      for (BufferBase* b = buf_static_.next(); b && !b->empty(); b = b->next()) {
        b->clear();
      }

      buf_ = &buf_static_;
    }

    bool WStringStream::empty() const
    {
      return !sink_ && (buf_ == &buf_static_) && (buf_static_.empty());
    }

    size_t WStringStream::length() const
    {
      size_t result = buf_static_.size();
      for (const BufferBase* b = buf_static_.next(); b && !b->empty(); b = b->next()) {
        result += b->size();
      }

      return result;
    }

    void WStringStream::flushSink()
    {
      sink_->write(buf_static_.buf(), buf_static_.size());
      buf_static_.clear();
    }

    namespace {

      template <typename T>
      auto append_signed(WStringStream& stream, T val)
        -> std::enable_if_t<std::is_signed<std::decay_t<T>>::value>
      {
        // type definitions
        using val_t = std::decay_t<T>;
        using uval_t = std::make_unsigned_t<val_t>;

        // convert to corresponding unsigned value, branchless
        const val_t mask = val >> (sizeof(T) * CHAR_BIT - 1);
        uval_t uval = (val + mask) ^ mask;

        // create buffer
        static constexpr auto bufSize = std::numeric_limits<uval_t>::digits10 + 2;
        char buf[bufSize];

        // write unsigned value to buffer
        char* ptr = buf + bufSize;
        do {
          *--ptr = static_cast<char>('0' + (uval % 10));
          uval /= 10;
        } while (uval > 0);

        // append sign if necessary
        if (val < 0) { *--ptr = '-'; }

        // append to buffer
        stream.append(ptr, buf + bufSize - ptr);
      }

      template <typename T>
      auto append_unsigned(WStringStream& stream, T val)
        -> std::enable_if_t<std::is_unsigned<std::decay_t<T>>::value>
      {
        // type definitions
        using uval_t = std::decay_t<T>;

        uval_t uval = val;

        // create buffer
        static constexpr auto bufSize = std::numeric_limits<uval_t>::digits10 + 2;
        char buf[bufSize];

        // write unsigned value to buffer
        char* ptr = buf + bufSize;
        do {
          *--ptr = static_cast<char>('0' + (uval % 10));
          uval /= 10;
        } while (uval > 0);

        // append to buffer
        stream.append(ptr, buf + bufSize - ptr);
      }
    }

    WStringStream& WStringStream::operator<< (signed char v)
    {
      append_signed(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (short v)
    {
      append_signed(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (long v)
    {
      append_signed(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (int v)
    {
      append_signed(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (long long v)
    {
      append_signed(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (unsigned char v)
    {
      append_unsigned(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (unsigned short v)
    {
      append_unsigned(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (unsigned long v)
    {
      append_unsigned(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (unsigned int v)
    {
      append_unsigned(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (unsigned long long v)
    {
      append_unsigned(*this, v);
      return *this;
    }

    WStringStream& WStringStream::operator<< (bool v)
    {
      if (v) {
        append("true", 4);
      }
      else {
        append("false", 5);
      }

      return *this;
    }

    WStringStream& WStringStream::operator<< (double d)
    {
      char buf[50];
      const int r = std::snprintf(buf, 50, "%g", d);
      append(buf, static_cast<size_t>(r));
      return *this;
    }

    WStringStream& WStringStream::operator<< (const WStringStream& s)
    {
      const size_t s_length = s.length();

      size_t remaining = 0;
      BufferBase* buf_last = nullptr;
      for (BufferBase* b = buf_; b && remaining < s_length; b = b->next()) {
        remaining += b->remaining();
        buf_last = b;
      }

      // no sink
      if (!sink_) {
        // check if free buffer space (plus one possibly newly allocated default
        // buffer) is big enough for all data; allocate an additional dynamic
        // buffer otherwise to ensure all data fits in 'this'
        if ((remaining + D_LEN) < s_length) {
          buf_last->setNext(std::make_unique<DynamicBuffer>(s_length - remaining));
        }
      }

      // sink
      else {
        // write everything directy to encapsulated 'sink' if there is not
        // enough remaining buffer space
        if (remaining < s_length) {
          flushSink();
          *sink_ << s;
          return *this;
        }
      }

      // copy all data; enough buffer space is guaranteed at this point
      for (const BufferBase* b = &s.buf_static_; b && !b->empty(); b = b->next()) {
        append(b->buf(), b->size());
      }

      return *this;
    }

    char WStringStream::operator[] (size_t idx) const
    {
      for (const BufferBase* b = &buf_static_; b; b = b->next()) {
        if (idx < b->size()) {
          return b->buf()[idx];
        }
        else {
          idx -= b->size();
        }
      }

      return '\0';
    }

    void WStringStream::append(char c)
    {
      if (!buf_->try_append(c)) {
        // no sink
        if (!sink_) {
          if (buf_->next()) {
            buf_ = buf_->next();
          }
          else {
            buf_ = buf_->setNext(std::make_unique<StaticBuffer<D_LEN>>());
          }
        }
        // sink
        else {
          flushSink();
        }

        buf_->append(c);
      }
    }

    void WStringStream::append(const char* s, size_t n)
    {
      if (!buf_->try_append(s, n)) {
        // no sink
        if (!sink_) {
          do {
            size_t r = buf_->remaining();
            if (r == 0) {
              if (buf_->next()) {
                buf_ = buf_->next();
              }
              else {
                buf_ = (n > D_LEN)
                  // dynamic buffers are allocated with another D_LEN extra bytes,
                  // thus being able to hold small followup strings that otherwise
                  // would require allocation of another StaticBuffer. This mostly
                  // counters the double allocation costs for DynamicBuffer if 
                  // dynamic buffers are needed only occasionally.
                  ? buf_->setNext(std::make_unique<DynamicBuffer>(n + D_LEN))
                  : buf_->setNext(std::make_unique<StaticBuffer<D_LEN>>());
              }

              // update 'r' for empty 'next' buffer
              r = buf_->capacity();
            }

            const size_t count = std::min(n, r);
            buf_->append(s, count);
            n -= count;
            s += count;

          } while (n > 0);
        }

        // sínk
        else {
          flushSink();
          if (n > buf_static_.capacity()) {
            sink_->write(s, n);
          }
          else {
            buf_static_.append(s, n);
          }
        }
      }
    }

    std::string WStringStream::str() const
    {
      std::string result;
      result.reserve(length());
      for (const BufferBase* b = &buf_static_; b && !b->empty(); b = b->next()) {
        result.append(b->buf(), b->size());
      }
      return result;
    }

#ifndef WT_DBO_STRINGSTREAM
    void WStringStream::asioBuffers(std::vector<AsioWrapper::asio::const_buffer>& result) const
    {
      size_t buf_cnt = 0;
      for (const BufferBase* b = &buf_static_; b && !b->empty(); b = b->next()) {
        ++buf_cnt;
      }

      result.reserve(result.size() + buf_cnt);
      for (const BufferBase* b = &buf_static_; b && !b->empty(); b = b->next()) {
        result.emplace_back(b->buf(), b->size());
      }
    }
#endif

    std::ostream& operator<< (std::ostream& os, const WStringStream& s)
    {
      for (const WStringStream::BufferBase* b = &s.buf_static_; b && !b->empty(); b = b->next()) {
        os.write(b->buf(), b->size());
      }
      return os;
    }

#ifdef WT_DBO_STRINGSTREAM
  } // namespace Dbo
#endif

} // namespace Wt
