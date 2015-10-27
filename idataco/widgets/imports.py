#!/usr/bin/python
########################################################################
# Copyright (c) 2015
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

from PySide import QtGui, QtCore
import idc
import logging
import struct

from . import TacoTabWidget

log = logging.getLogger("taco")


class TacoImports(TacoTabWidget):

    name = "Cuckoo Imports"
    short_name = "cuckoo_imports"

    def initVars(self):
        self._import_table = QtGui.QTableWidget()
        self._import_table.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self._import_table.setRowCount(0)
        self._import_table.setColumnCount(6)
        self._import_table.setHorizontalHeaderLabels(["Address","DLL","ProcName","ProcAddress","Type","IDA Name"])
        self._import_table.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
        copyAction = QtGui.QAction(self._import_table)
        copyAction.setText("Copy Cell Value")
        copyAction.triggered.connect(self.copyToClipboard)
        self._import_table.addAction(copyAction)
        renameAction = QtGui.QAction(self._import_table)
        renameAction.setText("Rename DWORDs to Proc Name")
        renameAction.triggered.connect(self.renameDword)
        self._import_table.addAction(renameAction)

        self.clipboard = QtGui.QClipboard()

    def initLayout(self):
        impt_table_layout = QtGui.QVBoxLayout()
        impt_table_layout.addWidget(self._import_table)
        self.setLayout(impt_table_layout)

    def load(self):
        self._import_table.clear()
        self._import_table.setHorizontalHeaderLabels(["Address", "DLL", "ProcName", "ProcAddress", "Type", "IDA Name"])
        self._import_table.itemDoubleClicked.connect(self.clickRow)
        self._import_table.setRowCount(len(self.parent.impts))
        self._import_table.setAlternatingRowColors(True)
        row = 0
        for impt in self.parent.impts:
            self._import_table.setItem(row, 0, QtGui.QTableWidgetItem(impt["addr"]))
            self._import_table.setItem(row, 1, QtGui.QTableWidgetItem(impt["dll"]))
            self._import_table.setItem(row, 2, QtGui.QTableWidgetItem(impt["proc_name"]))
            self._import_table.setItem(row, 3, QtGui.QTableWidgetItem(impt["proc_address"]))
            self._import_table.setItem(row, 4, QtGui.QTableWidgetItem(impt["type"]))
            self._import_table.setItem(row, 5, QtGui.QTableWidgetItem(idc.Name(int(impt["proc_address"], 16))))
            self._import_table.resizeRowToContents(row)
            row += 1
        self._import_table.setSortingEnabled(True)


    """
    Simple copy cell value to clipboard implementation
    """
    def copyToClipboard(self):
        item = self._import_table.item(self._import_table.currentRow(), self._import_table.currentColumn())
        self.clipboard.setText(item.text())

    """
    Attempts to rename all DWORD values with the detected import name
    """
    def renameDword(self):
        proc_addr = self._import_table.item(self._import_table.currentRow(), 3).text()
        proc_name = str(self._import_table.item(self._import_table.currentRow(), 2).text())
        renamed = 0
        if proc_addr:
            try:
                proc_addr = int(proc_addr, 16)
                proc_bin_str = " ".join([x.encode("hex") for x in struct.pack("<I", proc_addr)])
                next_dword = idc.FindBinary(idc.MinEA(), idc.SEARCH_DOWN|idc.SEARCH_NEXT, proc_bin_str)
                while next_dword != idc.BADADDR:
                    log.debug("Trying to fix-up 0x{:08x}".format(next_dword))
                    # DWORDs can be "inaccessible" for many reasons and it requires "breaking up" the data blobs
                    # and manually fixing them

                    # Reason 1: In a dword array in an unknown section
                    if idc.isUnknown(next_dword):
                        idc.MakeUnkn(next_dword, idc.DOUNK_EXPAND)
                        idc.MakeDword(next_dword)
                    # Reason 2: In a dword array in a data section
                    elif idc.isData(next_dword):
                        hd = idc.ItemHead(next_dword)
                        idc.MakeDword(hd)
                        idc.MakeDword(next_dword)
                    # Reason 3: In a dword array in a code section (validate via "dd <dword>,")
                    elif idc.isCode(next_dword) and idc.GetDisasm(next_dword).startswith("dd "):
                        hd = idc.ItemHead(next_dword)
                        idc.MakeDword(hd)
                        idc.MakeDword(next_dword)

                    # Only perform
                    if idc.Name(next_dword).startswith(("off_", "dword_")) or idc.Name(next_dword) == "":
                        success = idc.MakeNameEx(next_dword, proc_name, idc.SN_NOWARN|idc.SN_NON_AUTO)
                        i = 0
                        new_proc_name = proc_name
                        while not success and i < 10:
                            new_proc_name = "{}{}".format(proc_name, i)
                            success = idc.MakeNameEx(next_dword, new_proc_name, idc.SN_NOWARN|idc.SN_NON_AUTO)
                            i += 1
                        if success:
                            renamed += 1
                            item = self._import_table.item(self._import_table.currentRow(), 5)
                            item.setText("{}, {}".format(str(item.text()), new_proc_name))
                            log.debug("DWORD @ 0x{:08x} now has name {}".format(next_dword, new_proc_name))
                        else:
                            log.error("Unable to auto-rename successfully, terminating search")
                            break
                    else: log.debug("Value at 0x{:08x} does not meet renaming requirements".format(next_dword))
                    next_dword = idc.FindBinary(next_dword+4, idc.SEARCH_DOWN|idc.SEARCH_NEXT, proc_bin_str)
            except Exception, e:
                log.error("Error encountered: {}".format(e))
            log.debug("Renamed {:d} instances of {}".format(renamed, proc_name))

    def renameAllDwords(self):
        pass

    def clickRow(self):
        try:
            addr = int(self._import_table.item(self._import_table.currentRow(), 0).text(), 16)
            idc.Jump(addr)
        except Exception, e:
            log.error("Exception encountered: {}".format(e))

    def getTacoTab(self):
        taco_tab = QtGui.QWidget()
        layout = QtGui.QHBoxLayout()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
