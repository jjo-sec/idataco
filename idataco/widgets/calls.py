#!/usr/bin/python
########################################################################
# Copyright (c) 2015-2016
# Jason Jones <jason<at>jasonjon<dot>es>
# All rights reserved.
########################################################################
#
#  This file is part of IDA TACO
#
#  IDATACO is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import re
import idc

import idataco.util.qt as qt
from . import TacoTabWidget

import logging
log = logging.getLogger("taco.widgets")

class TacoCalls(TacoTabWidget):

    name = "Cuckoo Calls"
    short_name = "cuckoo_calls"
    description = """ Display Win32 API calls logged by Cuckoo Sandbox and allow for filtering by value and category.
                      Also support annotating calls with metadata from the log """

    _COLOR_MAP = {
            "registry":  qt.qcolor()(0xff, 0xc5, 0xc5),
            "filesystem": qt.qcolor()(0xff, 0xe3, 0xc5),
            "process": qt.qcolor()(0xc5, 0xe0, 0xff),
            #"threading": qt.qcolor()(0xa,0xa,0xa),
            "services": qt.qcolor()(0xcc, 0xc5, 0xff),
            "device": qt.qcolor()(0xcc, 0xc5, 0xff),
            "network": qt.qcolor()(0xd3, 0xff, 0xc5),
            "synchronization": qt.qcolor()(0xf9, 0xc5, 0xff),
            #"crypto": qt.qcolor()(0x9,0x9,0x9),
            "browser": qt.qcolor()(0xdf, 0xff, 0xdf),
    }

    def initVars(self):
        self._call_table = qt.qtablewidget()()
        self._call_table.setEditTriggers(qt.qabstractitemview().NoEditTriggers)
        self._call_table.setRowCount(0)
        self._call_table.setColumnCount(6)
        self._call_table.setHorizontalHeaderLabels(["Category","Caller","Parent  Caller","API","Return","Args"])
        self.clipboard = qt.qclipboard()
        self.setupTableContextMenu()
        self._marked_up = set()
        self._checkbox_map = {}

        # call color picker setup
        self._color_picker = qt.qcolordialog()()
        self._color_picker.setCurrentColor(qt.qcolor()(0xff,165,0x0))
        self._color_picker.blockSignals(True)
        self._color_picker.currentColorChanged.connect(self.chooseColor)
        self._color_picker.blockSignals(False)
        self._color_button = qt.qpushbutton()("")
        self._color_button.setStyleSheet("font-size:15px;background-color:#ffa500; border: 2px solid #222222")
        self._color_button.setFixedSize(15, 15)
        self._color_button.clicked.connect(self._color_picker.open)

        # func color picker setup
        self._func_color_picker = qt.qcolordialog()()
        self._func_color_picker.setCurrentColor(qt.qcolor()(0xff, 0xff, 0xff))
        self._func_color_picker.blockSignals(True)
        self._func_color_picker.currentColorChanged.connect(self.chooseFuncColor)
        self._func_color_picker.blockSignals(False)
        self._func_color_button = qt.qpushbutton()("")
        self._func_color_button.setStyleSheet("font-size:15px;background-color:#ffffff; border: 2px solid #222222")
        self._func_color_button.setFixedSize(15, 15)
        self._func_color_button.clicked.connect(self._func_color_picker.open)

    def initLayout(self):
        call_table_layout = qt.qvboxlayout()()
        filter_layout = qt.qhboxlayout()()
        markup_layout = qt.qhboxlayout()()
        markup_layout.setAlignment(qt.qtcore().Qt.AlignLeft)
        markup_layout.addWidget(qt.qlabel()("Choose Color: "))
        markup_layout.addWidget(self._color_button)
        markup_layout.addWidget(qt.qlabel()("Choose Function Color: "))
        markup_layout.addWidget(self._func_color_button)
        markup_layout.addWidget(qt.qlabel()("\t\t\tMarkup: "))
        markup_category_button = qt.qpushbutton()("Selected")
        markup_category_button.clicked.connect(self.markupCategories)
        markup_all_button = qt.qpushbutton()("All")
        markup_all_button.clicked.connect(self.markupAll)
        markup_remove_button = qt.qpushbutton()("Remove")
        markup_remove_button.clicked.connect(self.removeAllMarkup)
        markup_layout.addWidget(markup_category_button)
        markup_layout.addWidget(markup_all_button)
        markup_layout.addWidget(markup_remove_button)
        call_table_layout.addLayout(markup_layout)
        self._checkbox_layout = qt.qhboxlayout()()
        self._checkbox_layout.setAlignment(qt.qtcore().Qt.AlignLeft)
        self._checkbox_layout.addWidget(qt.qlabel()("Categories: "))
        call_table_layout.addLayout(self._checkbox_layout)
        self._filter_box = qt.qlineedit()()
        self._filter_box.setMaxLength(80)
        _filter_button = qt.qpushbutton()("Filter")
        _filter_button.clicked.connect(self.filterCallData)
        filter_layout.setAlignment(qt.qtcore().Qt.AlignLeft)
        filter_layout.addWidget(qt.qlabel()("Select: "))
        b_all = qt.qpushbutton()("All")
        width = b_all.fontMetrics().boundingRect("All").width() + 9
        b_all.setMaximumWidth(width)
        b_all.clicked.connect(self.selectAll)
        b_none = qt.qpushbutton()("None")
        width = b_all.fontMetrics().boundingRect("None").width() + 9
        b_none.setMaximumWidth(width)
        b_none.clicked.connect(self.selectNone)
        filter_layout.addWidget(b_all)
        filter_layout.addWidget(b_none)
        filter_layout.addWidget(qt.qlabel()("Filter Calls: "))
        filter_layout.addWidget(self._filter_box)
        filter_layout.addWidget(_filter_button)
        call_table_layout.addLayout(filter_layout)
        call_table_layout.addWidget(self._call_table)
        self.setLayout(call_table_layout)

    def setupTableContextMenu(self):
        self._call_table.setContextMenuPolicy(qt.qtcore().Qt.ActionsContextMenu)
        copyAction = qt.qaction()(self._call_table)
        copyAction.setText("Copy Cell Value")
        copyAction.triggered.connect(self.copyToClipboard)
        self._call_table.addAction(copyAction)
        markupAction = qt.qaction()(self._call_table)
        markupAction.setText("Add Markup to Selected Call")
        markupAction.triggered.connect(self.markUpItem)
        self._call_table.addAction(markupAction)
        unMarkupAction = qt.qaction()(self._call_table)
        unMarkupAction.setText("Remove Markup from Selected Call")
        unMarkupAction.triggered.connect(self.unMarkUpItem)
        self._call_table.addAction(unMarkupAction)
        log.debug("Creating Calls Tab")

    def filterCallData(self):
        unchecked = []
        for cat, cb in self._checkbox_map.items():
            if not cb.isChecked(): unchecked.append(cat)
        log.debug(unchecked)
        if self._filter_box.text():
            filter_text = self._filter_box.text().lower()
            log.debug(filter_text)
            for i in range(self._call_table.rowCount()):
                if self._call_table.item(i, 0).text() in unchecked:
                    self._call_table.setRowHidden(i, True)
                elif filter_text not in self._call_table.item(i, 3).text().lower() and filter_text not in self._call_table.item(i, 5).text().lower():
                    self._call_table.setRowHidden(i, True)
                else:
                    self._call_table.setRowHidden(i, False)
        else:
            for i in range(self._call_table.rowCount()):
                if self._call_table.item(i, 0).text() in unchecked:
                    self._call_table.setRowHidden(i, True)
                else:
                    self._call_table.setRowHidden(i, False)

    def load(self):
        for cat in sorted(list(self.parent.call_categories)):
            self._checkbox_map[cat] = qt.qcheckbox()(cat.capitalize())
        for cat in sorted(self._checkbox_map.keys()):
            cb = self._checkbox_map[cat]
            cb.setCheckState(qt.qtcore().Qt.Checked)
            cb.clicked.connect(self.filterCallData)
            self._checkbox_layout.addWidget(cb)
        self._call_table.clear()
        self._call_table.setHorizontalHeaderLabels(["Category","Caller","Parent  Caller","API","Return","Args"])
        header = self._call_table.horizontalHeader()
        header.setStretchLastSection(True)
        if self.parent.cuckoo_version.startswith(("1.3", "2.0")):
            self._call_table.itemDoubleClicked.connect(self.clickRow)
        self._call_table.setRowCount(len(self.parent.calls))
        row = 0
        for call in self.parent.calls:
            arg_str = "\r\n".join(["{}: {}".format(k, unicode(v)[:80].encode("unicode-escape")) for k, v in call["arguments"].items()])
            bg_color = self._COLOR_MAP.get(call.get("category", ""), qt.qcolor()(0xff, 0xff, 0xff))
            self._call_table.setItem(row, 0, qt.qtablewidgetitem()(call.get("category", "")))
            self._call_table.item(row, 0).setBackground(bg_color)
            call_addr = ""
            if self.parent.cuckoo_version.startswith("1.3"):
                call_addr = idc.PrevHead(int(call["caller"],16))
                call_addr = call.get("caller", "0x00000000") if call_addr == idc.BADADDR else "0x{:08x}".format(call_addr)
            # cuckoo 2.0 stores call stack in "stack", but only enabled in DEBUG
            if self.parent.cuckoo_version.startswith("2.0") and call["stacktrace"]:
                call_addr = call["stacktrace"][-1].split(" @ ")[-1]
            ret = call["return"] if "return" in call else str(call["return_value"])
            self._call_table.setItem(row, 1, qt.qtablewidgetitem()(call_addr))
            self._call_table.item(row, 1).setBackground(bg_color)
            self._call_table.setItem(row, 2, qt.qtablewidgetitem()(call.get("parentcaller", "")))
            self._call_table.item(row, 2).setBackground(bg_color)
            self._call_table.setItem(row, 3, qt.qtablewidgetitem()(call["api"]))
            self._call_table.item(row, 3).setBackground(bg_color)
            self._call_table.setItem(row, 4, qt.qtablewidgetitem()(ret))
            self._call_table.item(row, 4).setBackground(bg_color)
            self._call_table.setItem(row, 5, qt.qtablewidgetitem()(arg_str))
            self._call_table.item(row, 5).setBackground(bg_color)
            row += 1
        self._call_table.resizeRowsToContents()
        self._call_table.resizeColumnsToContents()
        self._call_table.setSortingEnabled(True)


    def clickRow(self):
        addr = int(self._call_table.item(self._call_table.currentRow(), 1).text(), 16)
        if addr:
            idc.Jump(addr)

    def markUpItem(self):
        markup_ea = int(self._call_table.item(self._call_table.currentRow(), 1).text(), 16)
        self.markupEa(markup_ea)
        self._marked_up.add(markup_ea)
        if self.parent.cuckoo_version.startswith("1.3"):
            markup_parent_ea = int(self._call_table.item(self._call_table.currentRow(), 2).text(), 16)
            self.markupEa(markup_parent_ea, colorFunc=False)
            self._marked_up.add(markup_parent_ea)
        api_name = self._call_table.item(self._call_table.currentRow(), 3).text()
        args = self._call_table.item(self._call_table.currentRow(), 5).text()
        self.addPosterior(markup_ea, api_name, args)

    def addPosterior(self, markup_ea, api_name, args):
        log.debug("Adding posterior lines")
        idc.MakeComm(markup_ea, str(api_name))
        idc.ExtLinB(markup_ea, 0, "api: {}".format(api_name))
        ln = 1
        for arg in re.split("\r?\n", args.strip()):
            idc.ExtLinB(markup_ea, ln, str(arg.strip()))
            ln += 1

    def markupEa(self, markup_ea, colorFunc=True):
        if markup_ea and markup_ea != idc.BADADDR:
            func_color = self._func_color_picker.currentColor()
            ea_color = self._color_picker.currentColor()
            log.debug("Coloring instructions for 0x{:08x}".format(markup_ea))
            idc.SetColor(markup_ea, idc.CIC_FUNC, int("0x{:02x}{:02x}{:02x}".format(*func_color.toTuple()[:3][::-1]), 16))
            if colorFunc:
                idc.SetColor(markup_ea, idc.CIC_ITEM, int("0x{:02x}{:02x}{:02x}".format(*ea_color.toTuple()[:3][::-1]), 16))

    def unMarkUpItem(self):
        markup_ea = int(self._call_table.item(self._call_table.currentRow(), 1).text(), 16)
        self.removeMarkup(markup_ea)
        if markup_ea in self._marked_up:
            self._marked_up.remove(markup_ea)
        if self.parent.cuckoo_version.startswith("1.3"):
            markup_parent_ea = int(self._call_table.item(self._call_table.currentRow(), 2).text(), 16)
            self.removeMarkup(markup_parent_ea)
            if markup_parent_ea in self._marked_up:
                self._marked_up.remove(markup_parent_ea)

    def removeMarkup(self, ea, force=False):
        if ea in self._marked_up or force:
            log.debug("Removing color")
            idc.SetColor(ea, idc.CIC_FUNC, 0xffffff)
            idc.SetColor(ea, idc.CIC_ITEM, 0xffffff)
            idc.MakeComm(ea, "")
            log.debug("Removing posterior lines")
            i = 0
            while idc.LineB(ea, i):
                idc.DelExtLnB(ea, i)
                i += 1

    def removeAllMarkup(self):
        for i in range(self._call_table.rowCount()):
            markup_ea = int(self._call_table.item(i, 1).text(), 16)
            self.removeMarkup(markup_ea, force=True)
        self._marked_up = set()

    def markupCategories(self):
        checked = []
        last_ea = idc.BADADDR
        for cat, cb in self._checkbox_map.items():
            if cb.isChecked():
                checked.append(cat)
        for i in range(self._call_table.rowCount()):
            if self._call_table.item(i, 0).text() in checked:
                markup_ea = int(self._call_table.item(i, 1).text(), 16)
                if markup_ea and markup_ea != idc.BADADDR and markup_ea != last_ea and markup_ea not in self._marked_up:
                    last_ea = markup_ea
                    self.markupEa(markup_ea)
                    api_name = self._call_table.item(i, 3).text()
                    args = self._call_table.item(i, 5).text()
                    self.addposterior(markup_ea, api_name, args)
                    self._marked_up.add(markup_ea)
                    if self.parent.cuckoo_version.startswith("1.3"):
                        markup_parent_ea = int(self._call_table.item(i, 2).text(), 16)
                        self.markupEa(markup_parent_ea)
                        self._marked_up.add(markup_parent_ea)


    def markupAll(self):
        last_ea = idc.BADADDR
        for i in range(self._call_table.rowCount()):
            ea = self._call_table
            markup_ea = int(self._call_table.item(i, 1).text(), 16)
            if markup_ea and markup_ea != idc.BADADDR and markup_ea != last_ea and markup_ea not in self._marked_up:
                self.markupEa(markup_ea)
                self._marked_up.add(markup_ea)
                api_name = self._call_table.item(i, 3).text()
                args = self._call_table.item(i, 5).text()
                self.addPosterior(markup_ea, api_name, args)
                if self.parent.cuckoo_version.startswith("1.3"):
                    markup_parent_ea = int(self._call_table.item(i, 2).text(), 16)
                    self.markupEa(markup_parent_ea, colorFunc=False)
                    self._marked_up.add(markup_parent_ea)

    def copyToClipboard(self):
        item = self._call_table.item(self._call_table.currentRow(), self._call_table.currentColumn())
        self._clipboard.setText(item.text())

    def selectAll(self):
        for cat, cb in self._checkbox_map.iteritems():
            cb.setCheckState(qt.qtcore().Qt.Checked)
        self.filterCallData()

    def selectNone(self):
        for cat, cb in self._checkbox_map.iteritems():
            cb.setCheckState(qt.qtcore().Qt.Unchecked)
        self.filterCallData()

    def chooseColor(self):
        color = self._color_picker.currentColor()
        self._color_button.setStyleSheet("font-size:40px;background-color:#{:02x}{:02x}{:02x};\
        border: 2px solid #222222".format(color.red(), color.green(), color.blue()))

    def chooseFuncColor(self):
        color = self._func_color_picker.currentColor()
        self._func_color_button.setStyleSheet("font-size:40px;background-color:#{:02x}{:02x}{:02x};\
        border: 2px solid #222222".format(color.red(), color.green(), color.blue()))

    def getTacoTab(self):
        taco_tab = qt.qwidget()()
        layout = qt.qhboxlayout()()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
