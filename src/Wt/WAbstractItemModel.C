/*
 * Copyright (C) 2008 Emweb bv, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#include "Wt/WAbstractItemModel.h"
#include "Wt/WEvent.h"
#include "Wt/WException.h"
#include "Wt/WItemSelectionModel.h"
#include "Wt/WLogger.h"
#include "Wt/WModelIndex.h"

#include "WebUtils.h"

#ifdef WT_WIN32
#define snprintf _snprintf
#endif

namespace {
  const char *DRAG_DROP_MIME_TYPE = "application/x-wabstractitemmodelselection";
}

namespace Wt {

LOGGER("WAbstractItemModel");

WAbstractItemModel::WAbstractItemModel()
{ }

WAbstractItemModel::~WAbstractItemModel()
{ }

bool WAbstractItemModel::canFetchMore(WT_MAYBE_UNUSED const WModelIndex& parent) const
{
  return false;
}

void WAbstractItemModel::fetchMore(WT_MAYBE_UNUSED const WModelIndex& parent)
{ }

WFlags<ItemFlag> WAbstractItemModel::flags(WT_MAYBE_UNUSED const WModelIndex& index) const
{
  return ItemFlag::Selectable;
}

WFlags<HeaderFlag> WAbstractItemModel::headerFlags(WT_MAYBE_UNUSED int section, WT_MAYBE_UNUSED Orientation orientation)
  const
{
  return None;
}

bool WAbstractItemModel::hasChildren(const WModelIndex& index) const
{
  return rowCount(index) > 0 && columnCount(index) > 0;
}

bool WAbstractItemModel::hasIndex(int row, int column,
                                  const WModelIndex& parent) const
{
  return (row >= 0
          && column >= 0
          && row < rowCount(parent)
          && column < columnCount(parent));
}

WAbstractItemModel::DataMap
WAbstractItemModel::itemData(const WModelIndex& index) const
{
  DataMap result;

  if (index.isValid()) {
#ifndef WT_TARGET_JAVA
    for (int i = 0; i <= ItemDataRole::BarBrushColor; ++i)
#else
    for (int i = 0; i <= ItemDataRole::BarBrushColor.value(); ++i)
#endif
      result[ItemDataRole(i)] = data(index, ItemDataRole(i));
    result[ItemDataRole::User] = data(index, ItemDataRole::User);
  }

  return result;
}

cpp17::any WAbstractItemModel::data(int row, int column, ItemDataRole role,
                                 const WModelIndex& parent) const
{
  return data(index(row, column, parent), role);
}

cpp17::any WAbstractItemModel::headerData(WT_MAYBE_UNUSED int section, WT_MAYBE_UNUSED Orientation orientation, ItemDataRole role) const
{
  if (role == ItemDataRole::Level)
    return cpp17::any((int)0);
  else
    return cpp17::any();
}

void WAbstractItemModel::sort(WT_MAYBE_UNUSED int column, WT_MAYBE_UNUSED SortOrder order)
{ }

void WAbstractItemModel::expandColumn(WT_MAYBE_UNUSED int column)
{ }

void WAbstractItemModel::collapseColumn(WT_MAYBE_UNUSED int column)
{ }

bool WAbstractItemModel::insertColumns(WT_MAYBE_UNUSED int column, WT_MAYBE_UNUSED int count, WT_MAYBE_UNUSED const WModelIndex& parent)
{
  return false;
}

bool WAbstractItemModel::insertRows(WT_MAYBE_UNUSED int column, WT_MAYBE_UNUSED int count, WT_MAYBE_UNUSED const WModelIndex& parent)
{
  return false;
}

bool WAbstractItemModel::removeColumns(WT_MAYBE_UNUSED int column, WT_MAYBE_UNUSED int count, WT_MAYBE_UNUSED const WModelIndex& parent)
{
  return false;
}

bool WAbstractItemModel::removeRows(WT_MAYBE_UNUSED int column, WT_MAYBE_UNUSED int count, WT_MAYBE_UNUSED const WModelIndex& parent)
{
  return false;
}

bool WAbstractItemModel::setData(WT_MAYBE_UNUSED const WModelIndex& index, WT_MAYBE_UNUSED const cpp17::any& value, WT_MAYBE_UNUSED ItemDataRole role)
{
  return false;
}

bool WAbstractItemModel::setHeaderData(WT_MAYBE_UNUSED int section, WT_MAYBE_UNUSED Orientation orientation, WT_MAYBE_UNUSED const cpp17::any& value, WT_MAYBE_UNUSED ItemDataRole role)
{
  return false;
}

bool WAbstractItemModel::setHeaderData(int section, const cpp17::any& value)
{
  return setHeaderData(section, Orientation::Horizontal, value);
}

bool WAbstractItemModel::setItemData(const WModelIndex& index,
                                     const DataMap& values)
{
  bool result = true;

  for (DataMap::const_iterator i = values.begin(); i != values.end(); ++i)
    // if (i->first != ItemDataRole::Edit)
      if (!setData(index, i->second, i->first))
        result = false;

  dataChanged().emit(index, index);

  return result;
}

bool WAbstractItemModel::insertColumn(int column, const WModelIndex& parent)
{
  return insertColumns(column, 1, parent);
}

bool WAbstractItemModel::insertRow(int row, const WModelIndex& parent)
{
  return insertRows(row, 1, parent);
}

bool WAbstractItemModel::removeColumn(int column, const WModelIndex& parent)
{
  return removeColumns(column, 1, parent);
}

bool WAbstractItemModel::removeRow(int row, const WModelIndex& parent)
{
  return removeRows(row, 1, parent);
}

bool WAbstractItemModel::setData(int row, int column, const cpp17::any& value,
                                 ItemDataRole role, const WModelIndex& parent)
{
  WModelIndex i = index(row, column, parent);

  if (i.isValid())
    return setData(i, value, role);
  else
    return false;
}

void WAbstractItemModel::reset()
{
  modelReset_.emit();
}

WModelIndex WAbstractItemModel::createIndex(int row, int column, void *ptr)
  const
{
  return WModelIndex(row, column, this, ptr);
}

WModelIndex WAbstractItemModel::createIndex(int row, int column, ::uint64_t id)
  const
{
  return WModelIndex(row, column, this, id);
}

void *WAbstractItemModel::toRawIndex(WT_MAYBE_UNUSED const WModelIndex& index) const
{
  return nullptr;
}

WModelIndex WAbstractItemModel::fromRawIndex(WT_MAYBE_UNUSED void* rawIndex) const
{
  return WModelIndex();
}

std::string WAbstractItemModel::mimeType() const
{
  return DRAG_DROP_MIME_TYPE;
}

std::vector<std::string> WAbstractItemModel::acceptDropMimeTypes() const
{
  std::vector<std::string> result;

  result.push_back(DRAG_DROP_MIME_TYPE);

  return result;
}

void WAbstractItemModel::copyData(const WModelIndex& sIndex,
                                  const WModelIndex& dIndex)
{
  if (dIndex.model() != this)
    throw WException("WAbstractItemModel::copyData(): dIndex must be an index of this model");

  DataMap values = itemData(dIndex);
  for (DataMap::const_iterator i = values.begin(); i != values.end(); ++i)
    setData(dIndex, cpp17::any(), i->first);

  auto source = sIndex.model();
  setItemData(dIndex, source->itemData(sIndex));
}

void WAbstractItemModel::dropEvent(const WDropEvent& e, DropAction action,
                                   int row, WT_MAYBE_UNUSED int column,
                                   const WModelIndex& parent)
{
  // TODO: For now, we assumes selectionBehavior() == RowSelection !

  WItemSelectionModel *selectionModel
    = dynamic_cast<WItemSelectionModel *>(e.source());
  if (selectionModel) {
    auto sourceModel = selectionModel->model();

    /*
     * (1) Insert new rows (or later: cells ?)
     */
    if (action == DropAction::Move || row == -1) {
      if (row == -1)
        row = rowCount(parent);

      if (!insertRows(row, selectionModel->selectedIndexes().size(), parent)) {
        LOG_ERROR("dropEvent(): could not insertRows()");
        return;
      }
    }

    /*
     * (2) Copy data
     */
    WModelIndexSet selection = selectionModel->selectedIndexes();

    int r = row;
    for (WModelIndexSet::const_iterator i = selection.begin();
         i != selection.end(); ++i) {
      WModelIndex sourceIndex = *i;
      if (selectionModel->selectionBehavior() ==
          SelectionBehavior::Rows) {
        WModelIndex sourceParent = sourceIndex.parent();

        for (int col = 0; col < sourceModel->columnCount(sourceParent); ++col) {
          WModelIndex s = sourceModel->index(sourceIndex.row(), col,
                                             sourceParent);
          WModelIndex d = index(r, col, parent);
          copyData(s, d);
        }

        ++r;
      }
    }

    /*
     * (3) Remove original data
     */
    if (action == DropAction::Move) {
      while (!selectionModel->selectedIndexes().empty()) {
        WModelIndex i = Utils::last(selectionModel->selectedIndexes());

        if (!sourceModel->removeRow(i.row(), i.parent())) {
          LOG_ERROR("dropEvent(): could not removeRows()");
          return;
        }
      }
    }
  }
}

void WAbstractItemModel::dropEvent(const WDropEvent& e, DropAction action,
                                   const WModelIndex& pindex, Wt::Side side)
{
  WItemSelectionModel *selectionModel
    = dynamic_cast<WItemSelectionModel *>(e.source());
  if (selectionModel) {
    auto sourceModel = selectionModel->model();

    const WModelIndex& parent = pindex.parent();
    int row = !pindex.isValid() ? rowCount() :
      side == Side::Bottom ? pindex.row()+1 : pindex.row();

    /*
     * (1) Insert new rows (or later: cells ?)
     */
    if (!insertRows(row, selectionModel->selectedIndexes().size(), parent)) {
      LOG_ERROR("dropEvent(): could not insertRows()");
      return;
    }

    /*
     * (2) Copy data
     */
    WModelIndexSet selection = selectionModel->selectedIndexes();

    int r = row;
    for (WModelIndexSet::const_iterator i = selection.begin();
         i != selection.end(); ++i) {
      WModelIndex sourceIndex = *i;
      if (selectionModel->selectionBehavior() ==
          SelectionBehavior::Rows) {
        WModelIndex sourceParent = sourceIndex.parent();

        for (int col = 0; col < sourceModel->columnCount(sourceParent); ++col) {
          WModelIndex s = sourceModel->index(sourceIndex.row(), col,
                                             sourceParent);
          WModelIndex d = index(r, col, parent);
          copyData(s, d);
        }

        ++r;
      }
    }

    /*
     * (3) Remove original data
     */
    if (action == DropAction::Move) {
      while (!selectionModel->selectedIndexes().empty()) {
        WModelIndex i = Utils::last(selectionModel->selectedIndexes());

        if (!sourceModel->removeRow(i.row(), i.parent())) {
          LOG_ERROR("dropEvent(): could not removeRows()");
          return;
        }
      }
    }
  }
}

void WAbstractItemModel::beginInsertColumns(const WModelIndex& parent,
                                            int first, int last)
{
  first_ = first;
  last_ = last;
  parent_ = parent;

  columnsAboutToBeInserted().emit(parent_, first, last);
}

void WAbstractItemModel::endInsertColumns()
{
  columnsInserted().emit(parent_, first_, last_);
}

void WAbstractItemModel::beginInsertRows(const WModelIndex& parent,
                                         int first, int last)
{
  first_ = first;
  last_ = last;
  parent_ = parent;

  rowsAboutToBeInserted().emit(parent, first, last);
}

void WAbstractItemModel::endInsertRows()
{
  rowsInserted().emit(parent_, first_, last_);
}

void WAbstractItemModel::beginRemoveColumns(const WModelIndex& parent,
                                            int first, int last)
{
  first_ = first;
  last_ = last;
  parent_ = parent;

  columnsAboutToBeRemoved().emit(parent, first, last);
}

void WAbstractItemModel::endRemoveColumns()
{
  columnsRemoved().emit(parent_, first_, last_);
}

void WAbstractItemModel::beginRemoveRows(const WModelIndex& parent,
                                         int first, int last)
{
  first_ = first;
  last_ = last;
  parent_ = parent;

  rowsAboutToBeRemoved().emit(parent, first, last);
}

void WAbstractItemModel::endRemoveRows()
{
  rowsRemoved().emit(parent_, first_, last_);
}

WModelIndexList WAbstractItemModel::match(const WModelIndex& start,
                                          ItemDataRole role,
                                          const cpp17::any& value,
                                          int hits,
                                          WFlags<MatchFlag> flags)
  const
{
  WModelIndexList result;

  const int rc = rowCount(start.parent());

  for (int i = 0; i < rc; ++i) {
    int row = start.row() + i;

    if (row >= rc) {
      if (!(flags & MatchFlag::Wrap))
        break;
      else
        row -= rc;
    }

    WModelIndex idx = index(row, start.column(), start.parent());
    cpp17::any v = data(idx, role);

    if (Impl::matchValue(v, value, flags)) {
      result.push_back(idx);
      if (hits != -1 && (int)result.size() == hits)
        break;
    }
  }

  return result;
}

}
