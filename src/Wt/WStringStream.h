// This may look like C code, but it's really -*- C++ -*-
/*
 * Copyright (C) 2011 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#ifndef WT_WSTRING_STREAM_H_
#define WT_WSTRING_STREAM_H_

#include <Wt/WDllDefs.h>
#include <cstring>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

#ifdef WT_ASIO_IS_BOOST_ASIO
namespace boost {
#endif
  namespace asio {
    class const_buffer;
  }
#ifdef WT_ASIO_IS_BOOST_ASIO
}
#endif

#if !defined(WT_DBO_STRINGSTREAM) || DOXYGEN_ONLY
#define WT_STRINGSTREAM_API WT_API
#else
#define WT_STRINGSTREAM_API WTDBO_API
#endif

namespace Wt {

#ifdef WT_DBO_STRINGSTREAM
  namespace Dbo {
#endif // WT_DBO_STRINGSTREAM

    /*!
     * \class WStringStream Wt/WStringStream.h Wt/WStringStream.h
     * \brief This is an efficient std::stringstream replacement.
     *
     * It is in particular more efficient when a relatively short string
     * is being composed from many different pieces (avoiding any memory
     * allocation all-together).
     *
     * Compared to std::stringstream, it also avoids overhead by not
     * supporting the formatting options of the latter, and by not making
     * use of the std::locale, which apparently hampers std::ostream
     * performance (%Wt internally uses UTF-8 encoding throughout).
     */
    class WT_STRINGSTREAM_API WStringStream
    {
    public:

      /*!
       * \brief An implementation of an output generator for appending data.
       *
       * \sa back_inserter()
       */
      struct WT_STRINGSTREAM_API iterator
      {
        struct WT_STRINGSTREAM_API char_proxy
        {
          char_proxy& operator= (char c) {
            stream_->append(c);
            return *this;
          }

        private:
          char_proxy(WStringStream* stream) : stream_(stream) { /* empty */ }
          WStringStream* stream_;

          friend struct iterator;
        };

        char_proxy operator * () { return char_proxy(stream_); }
        iterator& operator ++ () { return *this; }
        iterator  operator ++ (int) { return *this; }

      private:
        iterator(WStringStream* stream) : stream_(stream) { /* empty */ }
        WStringStream* stream_;

        friend class WStringStream;
      };

      /*!
       * \brief Default constructor.
       *
       * Creates a string stream.
       */
      WStringStream();

      /*!
       * \brief Copy constructor.
       */
      WStringStream(const WStringStream& rhs);

      /*!
       * \brief Move constructor.
       */
      WStringStream(WStringStream&& rhs) noexcept;

      /*!
       * \brief Destructor.
       */
      ~WStringStream();

      /*!
       * \brief Constructor with std::ostream sink.
       *
       * Creates a string stream which flushes contents to an
       * std::ostream, instead of relying on internal buffering. The
       * output may still be internally buffered (for performance
       * reasons), and this buffer is only flushed to the underlying ostream
       * when you delete the string stream.
       */
      WStringStream(std::ostream& sink);

      /*!
       * \brief Copy assignment operator.
       */
      WStringStream& operator= (const WStringStream& rhs);

      /*!
       * \brief Move assignment operator.
       */
      WStringStream& operator= (WStringStream&& rhs) noexcept;

      /*!
       * \brief Appends a character.
       */
      WStringStream& operator<< (char c) {
        append(c);
        return *this;
      }

      /*!
       * \brief Appends a C string.
       */
      WStringStream& operator<< (const char* s) {
        append(s, strlen(s));
        return *this;
      }

      /*!
       * \brief Appends a C++ string.
       */
      WStringStream& operator<< (const std::string& s) {
        append(s.c_str(), s.size());
        return *this;
      }

      /*!
       * \brief Appends a boolean.
       *
       * This is written to the stream as <tt>true</tt> or <tt>false</tt>.
       */
      WStringStream& operator<< (bool);

      /*!
       * \brief Appends an integer number.
       */
      WStringStream& operator<< (signed char);

      /*!
       * \brief Appends an integer number.
       */
      WStringStream& operator<< (short);

      /*!
       * \brief Appends an integer number.
       */
      WStringStream& operator<< (long);

      /*!
       * \brief Appends an integer number.
       */
      WStringStream& operator<< (int);

      /*!
       * \brief Appends an integer number.
       */
      WStringStream& operator<< (long long);

      /*!
       * \brief Appends an unsigned integer number.
       */
      WStringStream& operator<< (unsigned char);

      /*!
       * \brief Appends an unsigned integer number.
       */
      WStringStream& operator<< (unsigned short);

      /*!
       * \brief Appends an unsigned integer number.
       */
      WStringStream& operator<< (unsigned long);

      /*!
       * \brief Appends an unsigned integer number.
       */
      WStringStream& operator<< (unsigned int);

      /*!
       * \brief Appends an unsigned integer number.
       */
      WStringStream& operator<< (unsigned long long);

      /*!
       * \brief Appends a floating point number.
       */
      WStringStream& operator<< (double);

      /*!
       * \brief Appends a string stream.
       */
      WStringStream& operator<< (const WStringStream& s);

      /*!
       * \brief Returns a specific character inside the string stream.
       *
       * Returns the character at index \p idx. If \p idx is
       * out of range, a <tt>'\0'</tt> character is returned.
       */
      char operator[] (size_t idx) const;

      /*!
       * \brief Appends a character.
       */
      void append(char c);

      /*!
       * \brief Appends a string.
       *
       * Appends \p n bytes from the given string.
       */
      void append(const char* s, size_t n);

      /*!
       * \brief Iterator for appending.
       */
      iterator back_inserter() {
        return iterator(this);
      }

      /*!
       * \brief Returns the contents as a C++ string.
       *
       * \attention The behaviour is only defined for a string stream
       * with internal buffering.
       */
      std::string str() const;

#ifndef WT_DBO_STRINGSTREAM
#ifdef WT_ASIO_IS_BOOST_ASIO
      void asioBuffers(std::vector<boost::asio::const_buffer>& result) const;
#else
      void asioBuffers(std::vector<asio::const_buffer>& result) const;
#endif
#endif // WT_DBO_STRINGSTREAM

      /*!
       * \brief Returns whether the contents is empty.
       *
       * \attention The behaviour is only defined for a string stream
       * with internal buffering.
       */
      bool empty() const;

      /*!
       * \brief Returns the total length.
       *
       * \attention The behaviour is only defined for a string stream
       * with internal buffering.
       */
      size_t length() const;

      /*!
       * \brief Clears the contents.
       *
       * \attention The behaviour is only defined for a string stream
       * with internal buffering.
       */
      void clear();

      // no-op for C++, but needed for Java
      void spool(std::ostream&) { }

    private:

      // declaration of internal BufferBase helper class
      struct BufferBase
      {
        BufferBase(const BufferBase& rhs) = delete;
        BufferBase(BufferBase&& rhs) = delete;
        virtual ~BufferBase();

        BufferBase& operator = (const BufferBase& rhs) = delete;
        BufferBase& operator = (BufferBase&& rhs) = delete;

        const char* buf() const;
        size_t capacity() const;
        size_t size() const;
        size_t remaining() const;
        BufferBase* setNext(std::unique_ptr<BufferBase> next);
        BufferBase* next() const;
        bool try_append(char c);
        bool try_append(const char* c, size_t n);
        void append(char c);
        void append(const char* c, size_t n);
        bool empty() const;
        void clear();

      protected:

        BufferBase(char* buf, size_t capacity, size_t size);

        char* const first_;
        char* const last_;
        char* curr_;
        std::unique_ptr<BufferBase> next_;
      };

      // declaration/definition of internal StaticBuffer helper class
      template <size_t N>
      struct StaticBuffer final
        : BufferBase
      {
        StaticBuffer() : BufferBase(buf_internal_, N, 0) { /* empty */ };
        StaticBuffer(StaticBuffer&& rhs) noexcept : BufferBase(buf_internal_, N, rhs.size()) {
          std::memcpy(buf_internal_, rhs.buf_internal_, rhs.size());
          next_ = std::move(rhs.next_);
        }
        ~StaticBuffer() final = default;

        StaticBuffer& operator= (StaticBuffer&& rhs) noexcept {
          std::memcpy(buf_internal_, rhs.buf_internal_, rhs.size());
          curr_ = first_ + rhs.size();
          next_ = std::move(rhs.next_);
          return *this;
        }

      private:
        char buf_internal_[N];
      };

      // forward declaration of internal DynamicBuffer helper class
      struct DynamicBuffer;

      // buffer related constants
      static constexpr size_t S_LEN = 1024;
      static constexpr size_t D_LEN = 2048;

      // member variables
      StaticBuffer<S_LEN> buf_static_;
      BufferBase* buf_;
      std::ostream* sink_;

      void flushSink();

      friend WT_STRINGSTREAM_API std::ostream& operator<<(std::ostream& os, const WStringStream& s);
    };

    /*!
     * \brief Print the string stream to an ostream.
     */
    WT_STRINGSTREAM_API std::ostream& operator<<(std::ostream& os, const WStringStream& s);

#ifdef WT_DBO_STRINGSTREAM
  } // namespace Dbo
#endif // WT_DBO_STRINGSTREAM

} // namespace Wt

#endif // WT_WSTRING_STREAM_H_
