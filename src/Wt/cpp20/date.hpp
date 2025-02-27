// This may look like C code, but it's really -*- C++ -*-
/*
 * Copyright (C) 2021 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#ifndef WT_CPP20_DATE_HPP
#define WT_CPP20_DATE_HPP

#include <Wt/WConfig.h>

#if defined(WT_DATE_TZ_USE_STD)

#include <chrono>

namespace Wt::cpp20 {

namespace date = std::chrono;

}

#else

#include <Wt/Date/date.h>

namespace Wt {
namespace cpp20 {

//! @cond Doxygen_Suppress
namespace date = ::date;
//! @endcond

}
}

#endif

#endif // WT_CPP20_DATE_HPP
