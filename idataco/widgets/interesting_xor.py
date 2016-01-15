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

import idaapi
import idc
import idautils

import idataco.util.qt as qt
from . import TacoTabWidget

import logging

log = logging.getLogger("taco.widgets")


class TacoInterestingXOR(TacoTabWidget):
    name = "Interesting XORs"
    short_name = "interesting_xor"
    description = """ Attempt to locate and document all XOR instructions potentially resulting in a non-zero output.
                      Also attempt detection of whether or not the XOR occurred in a loop """

    def initVars(self):
        self._interesting_xors = []
        self._interesting_xor_table = qt.qtablewidget()()
        self._interesting_xor_table.setRowCount(1)
        self._interesting_xor_table.setColumnCount(3)
        self._interesting_xor_table.setHorizontalHeaderLabels(("Function", "Address", "Loop", "Disassembly"))

    def initLayout(self):
        layout = qt.qvboxlayout()()
        layout.addWidget(self._interesting_xor_table)
        self.setLayout(layout)

    def click_row(self):
        addr = self._interesting_xor_table.item(self._interesting_xor_table.currentRow(), 1).text().strip()
        addr= int(addr, 16)
        idc.Jump(addr)

    def load(self):
        self.find_interesting_xors()
        self._interesting_xor_table.clear()
        self._interesting_xor_table.setColumnCount(4)
        self._interesting_xor_table.setHorizontalHeaderLabels(("Function", "Address", "Loop", "Disassembly"))
        self._interesting_xor_table.itemDoubleClicked.connect(self.click_row)
        self._interesting_xor_table.setRowCount(len(self._interesting_xors))
        row = 0
        for interesting_xor in self._interesting_xors:
            self._interesting_xor_table.setItem(row, 0, qt.qtablewidgetitem()(interesting_xor["func"]))
            self._interesting_xor_table.setItem(row, 1, qt.qtablewidgetitem()("0x{:08X}".format(interesting_xor["addr"])))
            self._interesting_xor_table.setItem(row, 2, qt.qtablewidgetitem()(str(interesting_xor["loop"])))
            self._interesting_xor_table.setItem(row, 3, qt.qtablewidgetitem()(interesting_xor["disasm"]))
            self._interesting_xor_table.resizeRowToContents(row)
            row += 1
        self._interesting_xor_table.setSortingEnabled(True)
        self._interesting_xor_table.resizeRowsToContents()
        self._interesting_xor_table.resizeColumnsToContents()


    """
    Locates all non-zero XOR instructions and also marks whether they are in a loop
    """
    def find_interesting_xors(self):
        next_xor = idc.FindText(idc.MinEA(), idc.SEARCH_DOWN|idc.SEARCH_NEXT, 0, 0, "xor")
        while next_xor != idc.BADADDR:
            if idc.GetOpnd(next_xor, 0) != idc.GetOpnd(next_xor, 1):
                entry = {"func":"", "addr": next_xor, "loop":False, "disasm": idc.GetDisasm(next_xor)}
                func = idaapi.get_func(next_xor)
                if func:
                    entry["func"] = idaapi.get_name(idc.BADADDR, func.startEA)
                    heads = idautils.Heads(next_xor, func.endEA)
                    lxors = []
                    for head in heads:
                        if idc.GetMnem(head).startswith('j'):
                            jmp_addr = idc.GetOperandValue(head,0)
                            if jmp_addr < next_xor and jmp_addr > func.startEA:
                                entry["loop"] = True
                                break
                self._interesting_xors.append(entry)
            next_xor = idc.FindText(idc.NextHead(next_xor), idc.SEARCH_DOWN|idc.SEARCH_NEXT, 0, 0, "xor")

    def getTacoTab(self):
        taco_tab = qt.qwidget()()
        layout = qt.qvboxlayout()()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
