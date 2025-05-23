/*
 * Copyright (C) 2016 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include "Wt/WApplication.h"
#include "Wt/WBoxLayout.h"
#include "Wt/WContainerWidget.h"
#include "Wt/WEnvironment.h"
#include "Wt/WLogger.h"

#include "StdGridLayoutImpl2.h"
#include "FlexLayoutImpl.h"
#include "DomElement.h"
#include "ResizeSensor.h"
#include "WebUtils.h"

#ifndef WT_DEBUG_JS
#include "js/FlexLayoutImpl.min.js"
#endif

namespace Wt {

WT_MAYBE_UNUSED LOGGER("FlexLayout");

FlexLayoutImpl::FlexLayoutImpl(WLayout *layout, Impl::Grid& grid)
  : StdLayoutImpl(layout),
    grid_(grid),
    canAdjustLayout_(false)
{
  const char *THIS_JS = "js/FlexLayoutImpl.js";

  WApplication *app = WApplication::instance();

  if (!app->javaScriptLoaded(THIS_JS)) {
    LOAD_JAVASCRIPT(app, THIS_JS, "FlexLayout", wtjs1);
  }

  WContainerWidget *c = container();

  if (c) {
    c->setFlexBox(true);
  }
}

bool FlexLayoutImpl::itemResized(WT_MAYBE_UNUSED WLayoutItem* item)
{
  /*
   * Actually, we should only return true if the direct child's
   * visibility changed. We need an itemVisibilityChanged() ?
   */
  return true;
}

bool FlexLayoutImpl::parentResized()
{
  return false;
}

void FlexLayoutImpl::updateDom(DomElement& parent)
{
  WApplication *app = WApplication::instance();

  DomElement *div = DomElement::getForUpdate(elId_, DomElementType::DIV);

  bool skipLayoutAdjust = false;
  Orientation orientation = getOrientation();
  if (grid_.items_.size() > 0) {
    auto layoutParentWidget = item(orientation, 0).item_->parentWidget();
    if (layoutParentWidget && !layoutParentWidget->isEnabled()) {
      skipLayoutAdjust = true;
    }
  }


  std::vector<int> orderedInserts;
  for (unsigned i = 0; i < addedItems_.size(); ++i)
    orderedInserts.push_back(indexOf(addedItems_[i], orientation));

  Utils::sort(orderedInserts);

  int totalStretch = getTotalStretch(orientation);

  for (unsigned i = 0; i < orderedInserts.size(); ++i) {
    int pos = orderedInserts[i];
    DomElement *el = createElement(orientation, pos, totalStretch, app);
    div->insertChildAt(el, pos);
  }

  addedItems_.clear();

  for (unsigned i = 0; i < removedItems_.size(); ++i)
    div->callJavaScript(WT_CLASS ".remove('" + removedItems_[i] + "');",
                        true);

  removedItems_.clear();

  if (canAdjustLayout_) {
    div->callMethod("layout.adjust()");
  }

  if (!canAdjustLayout_ && skipLayoutAdjust) {
    canAdjustLayout_ = true;
  }

  parent.addChild(div);
}

FlexLayoutImpl::~FlexLayoutImpl()
{
  WApplication *app = WApplication::instance();

  if (parentLayoutImpl() == nullptr) {
    if (container() == app->root()) {
      app->setBodyClass("");
      app->setHtmlClass("");
    }

    WContainerWidget *c = container();

    if (c) {
      c->setFlexBox(false);
    }
  }
}

int FlexLayoutImpl::minimumHeightForRow(int row) const
{
  int minHeight = 0;

  const unsigned colCount = grid_.columns_.size();
  for (unsigned j = 0; j < colCount; ++j) {
    WLayoutItem *item = grid_.items_[row][j].item_.get();
    if (item)
      minHeight = std::max(minHeight, getImpl(item)->minimumHeight());
  }

  return minHeight;
}

int FlexLayoutImpl::minimumWidthForColumn(int col) const
{
  int minWidth = 0;

  const unsigned rowCount = grid_.rows_.size();
  for (unsigned i = 0; i < rowCount; ++i) {
    WLayoutItem *item = grid_.items_[i][col].item_.get();
    if (item)
      minWidth = std::max(minWidth, getImpl(item)->minimumWidth());
  }

  return minWidth;
}

int FlexLayoutImpl::maximumHeightForRow(int row) const
{
  int maxHeight = std::numeric_limits<int>::max();
  bool isConstrained = false;
  const unsigned colCount = grid_.columns_.size();
  for (unsigned j = 0; j < colCount; ++j) {
    WLayoutItem *item = grid_.items_[row][j].item_.get();
    if (item) {
      int itemMaxHeight = getImpl(item)->maximumHeight();
      if (itemMaxHeight > 0) {
        if (isConstrained) {
          maxHeight = std::min(maxHeight, itemMaxHeight);
        } else {
          maxHeight = itemMaxHeight;
          isConstrained = true;
        }
      }
    }
  }
  if (!isConstrained) {
    maxHeight = 0;
  }
  return maxHeight;
}

int FlexLayoutImpl::maximumWidthForColumn(int col) const
{
  int maxWidth = std::numeric_limits<int>::max();
  bool isConstrained = false;
  const unsigned rowCount = grid_.rows_.size();
  for (unsigned i = 0; i < rowCount; ++i) {
    WLayoutItem *item = grid_.items_[i][col].item_.get();
    if (item) {
      int itemMaxWidth = getImpl(item)->maximumWidth();
      if (itemMaxWidth > 0) {
        if (isConstrained) {
          maxWidth = std::min(maxWidth, itemMaxWidth);
        } else {
          maxWidth = itemMaxWidth;
          isConstrained = true;
        }
      }
    }
  }
 if (!isConstrained) {
    maxWidth = 0;
  }
  return maxWidth;
}

int FlexLayoutImpl::minimumWidth() const
{
  const unsigned colCount = grid_.columns_.size();

  int total = 0;

  for (unsigned i = 0; i < colCount; ++i)
    total += minimumWidthForColumn(i);

  return total + (colCount-1) * grid_.horizontalSpacing_;
}

int FlexLayoutImpl::minimumHeight() const
{
  const unsigned rowCount = grid_.rows_.size();

  int total = 0;

  for (unsigned i = 0; i < rowCount; ++i)
    total += minimumHeightForRow(i);

  return total + (rowCount-1) * grid_.verticalSpacing_;
}

int FlexLayoutImpl::maximumWidth() const
{
  const unsigned colCount = grid_.columns_.size();

  int total = 0;

  for (unsigned i = 0; i < colCount; ++i) {
    int colMax = maximumWidthForColumn(i);
    if (colMax == 0) {
      return 0;
    }
    total += colMax;
  }

  return total + (colCount-1) * grid_.horizontalSpacing_;
}

int FlexLayoutImpl::maximumHeight() const
{
  const unsigned rowCount = grid_.rows_.size();

  int total = 0;

  for (unsigned i = 0; i < rowCount; ++i) {
    int rowMax = maximumHeightForRow(i);
    if (rowMax == 0) {
      return 0;
    }
    total += rowMax;
  }

  return total + (rowCount-1) * grid_.verticalSpacing_;
}

void FlexLayoutImpl::itemAdded(WLayoutItem *item)
{
  addedItems_.push_back(item);
  update();
}

void FlexLayoutImpl::itemRemoved(WLayoutItem *item)
{
  Utils::erase(addedItems_, item);
  removedItems_.push_back(getImpl(item)->id());
  update();
}

int FlexLayoutImpl::count(WT_MAYBE_UNUSED Orientation orientation) const
{
  return grid_.rows_.size() * grid_.columns_.size();
}

Impl::Grid::Section& FlexLayoutImpl::section(Orientation orientation, int i)
{
  if (orientation == Orientation::Horizontal)
    return grid_.columns_[i];
  else
    return grid_.rows_[i];
}

Impl::Grid::Item& FlexLayoutImpl::item(Orientation orientation, int i)
{
  if (orientation == Orientation::Horizontal)
    return grid_.items_[0][i];
  else
    return grid_.items_[i][0];
}

DomElement *FlexLayoutImpl::createDomElement(DomElement *parent,
                                             WT_MAYBE_UNUSED bool fitWidth,
                                             WT_MAYBE_UNUSED bool fitHeight,
                                             WApplication *app)
{
  addedItems_.clear();
  removedItems_.clear();

  int margin[] = { 0, 0, 0, 0 };

  DomElement *result;

  if (layout()->parentLayout() == nullptr) {
    /*
     * If it is a top-level layout (as opposed to a nested layout),
     * configure overflow of the container.
     */
    if (container() == app->root()) {
      /*
       * Reset body,html default paddings and so on if we are doing layout
       * in the entire document.
       */
      app->setBodyClass(app->bodyClass() + " Wt-layout");
      app->setHtmlClass(app->htmlClass() + " Wt-layout");

      parent->setProperty(Property::StyleBoxSizing, "border-box");
    }

#ifndef WT_TARGET_JAVA
    layout()->getContentsMargins(margin + 3, margin, margin + 1, margin + 2);
#else // WT_TARGET_JAVA
    margin[3] = layout()->getContentsMargin(Side::Left);
    margin[0] = layout()->getContentsMargin(Side::Top);
    margin[1] = layout()->getContentsMargin(Side::Right);
    margin[2] = layout()->getContentsMargin(Side::Bottom);
#endif // WT_TARGET_JAVA

    Orientation orientation = getOrientation();

    if (orientation == Orientation::Horizontal) {
      margin[3] = std::max(0, margin[3]);
      margin[1] = std::max(0, margin[1]);
    } else {
      margin[0] = std::max(0, margin[0]);
      margin[2] = std::max(0, margin[2]);
    }

    ResizeSensor::applyIfNeeded(container());

    result = parent;
    elId_ = container()->id();
  } else {
    result = DomElement::createNew(DomElementType::DIV);
    elId_ = id();
    result->setId(elId_);
    result->setProperty(Property::StyleDisplay, styleDisplay());
  }

  if (margin[0] != 0 || margin[1] != 0 || margin[2] != 0 || margin[3] != 0) {
    WStringStream paddingProperty;
    paddingProperty << margin[0] << "px " << margin[1] << "px "
                    << margin[2] << "px " << margin[3] << "px";
    result->setProperty(Property::StylePadding, paddingProperty.str());
  }

  // FIXME minsize/maxsize

  result->setProperty(Property::StyleFlexFlow, styleFlex());

  Orientation orientation = getOrientation();

  int c = count(orientation);

  int totalStretch = getTotalStretch(orientation);

  for (int i = 0; i < c; ++i) {
    DomElement *el = createElement(orientation, i, totalStretch, app);
    result->addChild(el);
  }

  WStringStream js;
  js << "layout=new " WT_CLASS ".FlexLayout("
     << app->javaScriptClass() << ",'" << elId_ << "');";
  result->callMethod(js.str());

  return result;
}

std::string FlexLayoutImpl::styleDisplay() const
{
  return container()->isInline() ? "inline-flex" : "flex";
}

std::string FlexLayoutImpl::styleFlex() const
{
  switch (getDirection()) {
  case LayoutDirection::LeftToRight:
    return "row";
  case LayoutDirection::RightToLeft:
    return "row-reverse";
  case LayoutDirection::TopToBottom:
    return "column";
  case LayoutDirection::BottomToTop:
    return "column-reverse";
  }
  return "";
}

int FlexLayoutImpl::getTotalStretch(Orientation orientation)
{
  int totalStretch = 0;

  int c = count(orientation);
  for (int i = 0; i < c; ++i) {
    Impl::Grid::Section& s = section(orientation, i);
    Impl::Grid::Item& it = item(orientation, i);
    if (!it.item_.get()->widget() ||
        !it.item_.get()->widget()->isHidden())
      totalStretch += std::max(0, s.stretch_);
  }

  return totalStretch;
}

int FlexLayoutImpl::indexOf(WLayoutItem *it, Orientation orientation)
{
  int c = count(orientation);

  for (int i = 0; i < c; ++i)
    if (item(orientation, i).item_.get() == it)
      return i;

  return -1;
}

LayoutDirection FlexLayoutImpl::getDirection() const
{
  WBoxLayout *boxLayout = dynamic_cast<WBoxLayout *>(layout());
  if (boxLayout)
    return boxLayout->direction();
  else
    return LayoutDirection::LeftToRight;
}

Orientation FlexLayoutImpl::getOrientation() const
{
  switch (getDirection()) {
  case LayoutDirection::LeftToRight:
  case LayoutDirection::RightToLeft:
    return Orientation::Horizontal;
  case LayoutDirection::TopToBottom:
  case LayoutDirection::BottomToTop:
    return Orientation::Vertical;
  }
  return Orientation::Horizontal;
}

DomElement *FlexLayoutImpl::createElement(Orientation orientation,
                                          int index,
                                          int totalStretch,
                                          WApplication *app)
{
  Impl::Grid::Item& it = item(orientation, index);
  Impl::Grid::Section& s = section(orientation, index);

  DomElement *el
    = getImpl(it.item_.get())->createDomElement(nullptr, true, true, app);
  if (dynamic_cast<StdGridLayoutImpl2*>(getImpl(it.item_.get()))) {
    DomElement *wrapEl = DomElement::createNew(DomElementType::DIV);
    wrapEl->addChild(el);
    el = wrapEl;
  }

  int m[] = { 0, 0, 0, 0 };
  FlexLayoutImpl *flexImpl = dynamic_cast<FlexLayoutImpl*>(getImpl(it.item_.get()));
  if (flexImpl) {
    Orientation elOrientation = flexImpl->getOrientation();
    if (elOrientation == Orientation::Horizontal) {
      m[3] -= (flexImpl->grid_.horizontalSpacing_) / 2;
      m[1] -= (flexImpl->grid_.horizontalSpacing_ + 1) / 2;
    } else {
      m[0] -= (flexImpl->grid_.verticalSpacing_) / 2;
      m[2] -= (flexImpl->grid_.horizontalSpacing_ + 1) / 2;
    }
  }

  AlignmentFlag hAlign = it.alignment_ & AlignHorizontalMask;
  AlignmentFlag vAlign = it.alignment_ & AlignVerticalMask;

  /*
   * If not justifying along main axis, then we need to wrap inside
   * an additional (flex) element
   */
  if (orientation == Orientation::Horizontal) {
    if (hAlign != static_cast<AlignmentFlag>(0)) {
      el->setProperty(Property::StyleFlex, "0 0 auto");

      DomElement *wrap = DomElement::createNew(DomElementType::DIV);
      wrap->setId("w" + el->id());
      wrap->setProperty(Property::StyleDisplay, styleDisplay());
      wrap->setProperty(Property::StyleFlexFlow, styleFlex());
      wrap->addChild(el);
      el = wrap;

      switch (hAlign) {
      case AlignmentFlag::Left:
        el->setProperty(Property::StyleJustifyContent, "flex-start");
        break;
      case AlignmentFlag::Center:
        el->setProperty(Property::StyleJustifyContent, "center");
        break;
      case AlignmentFlag::Right:
        el->setProperty(Property::StyleJustifyContent, "flex-end");
      default:
        break;
      }
    }

    if (vAlign != static_cast<AlignmentFlag>(0))
      switch (vAlign) {
      case AlignmentFlag::Top:
        el->setProperty(Property::StyleAlignSelf, "flex-start");
        break;
      case AlignmentFlag::Middle:
        el->setProperty(Property::StyleAlignSelf, "center");
        break;
      case AlignmentFlag::Bottom:
        el->setProperty(Property::StyleAlignSelf, "flex-end");
        break;
      case AlignmentFlag::Baseline:
        el->setProperty(Property::StyleAlignSelf, "baseline");
      default:
        break;
      }
  } else {
    if (vAlign != static_cast<AlignmentFlag>(0)) {
      el->setProperty(Property::StyleFlex, "0 0 auto");

      DomElement *wrap = DomElement::createNew(DomElementType::DIV);
      wrap->setId("w" + el->id());
      wrap->setProperty(Property::StyleDisplay, styleDisplay());
      wrap->setProperty(Property::StyleFlexFlow, styleFlex());
      wrap->addChild(el);
      el = wrap;

      switch (vAlign) {
      case AlignmentFlag::Top:
        el->setProperty(Property::StyleJustifyContent, "flex-start");
        break;
      case AlignmentFlag::Middle:
        el->setProperty(Property::StyleJustifyContent, "center");
        break;
      case AlignmentFlag::Bottom:
        el->setProperty(Property::StyleJustifyContent, "flex-end");
      default:
        break;
      }
    }

    if (hAlign != static_cast<AlignmentFlag>(0))
      switch (hAlign) {
      case AlignmentFlag::Left:
        el->setProperty(Property::StyleAlignSelf, "flex-start");
        break;
      case AlignmentFlag::Center:
        el->setProperty(Property::StyleAlignSelf, "center");
        break;
      case AlignmentFlag::Right:
        el->setProperty(Property::StyleAlignSelf, "flex-end");
        break;
      default:
        break;
      }
  }

  {
    WStringStream flexProperty;
    int stretch = std::max(0, s.stretch_);
    int flexGrow = totalStretch == 0 ? 1 : stretch;
    int flexShrink = totalStretch == 0 ? 1 : (stretch == 0 ? 0 : 1);
    flexProperty << flexGrow << ' ' << flexShrink << ' ' << s.initialSize_.cssText();
    if (stretch == 0)
      el->setAttribute("flg", "0");
    el->setProperty(Property::StyleFlex, flexProperty.str());
  }

  switch (getDirection()) {
  case LayoutDirection::LeftToRight:
    if (index != 0) {
      m[3] += (grid_.horizontalSpacing_ + 1) / 2;
    }
    if (index != count(orientation)-1) {
      m[1] += (grid_.horizontalSpacing_) / 2;
    }
    break;

  case LayoutDirection::RightToLeft:
    if (index != 0) {
      m[1] += (grid_.horizontalSpacing_ + 1) / 2;
    }
    if (index != count(orientation)-1) {
      m[3] += (grid_.horizontalSpacing_) / 2;
    }
    break;

  case LayoutDirection::TopToBottom:
    if (index != 0) {
      m[0] += (grid_.horizontalSpacing_ + 1) / 2;
    }
    if (index != count(orientation)-1) {
      m[2] += (grid_.horizontalSpacing_) / 2;
    }
    break;

  case LayoutDirection::BottomToTop:
    if (index != 0) {
      m[2] += (grid_.horizontalSpacing_ + 1) / 2;
    }
    if (index != count(orientation)-1) {
      m[0] += (grid_.horizontalSpacing_) / 2;
    }
    break;
  }

  if (m[0] != 0 || m[1] != 0 || m[2] != 0 || m[3] != 0) {
    WStringStream marginProperty;
    marginProperty << m[0] << "px " << m[1] << "px "
                   << m[2] << "px " << m[3] << "px";
    el->setProperty(Property::StyleMargin, marginProperty.str());
  }

  return el;
}

}
