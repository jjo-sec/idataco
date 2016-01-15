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

"""
original code by Aaron Portnoy / Zef Cekaj, Exodus Intelligence
Updated and modified by Jason Jones
"""

import idaapi
import idc

import idataco.util.qt as qt
from . import TacoTabWidget

from collections import defaultdict

import logging

log = logging.getLogger("taco.widgets")


class TacoSwitchJumps(TacoTabWidget):

    name = "Switch Jumps"
    short_name = "switch_jumps"
    description = """ Attempt to locate all known Switch Jumps (case statements) and display detailed information on each """

    def initVars(self):
        self.byte_strings = {}
        self._switch_tree = qt.qtreewidget()()
        self._switch_tree.setHeaderLabels(("Names", "# Cases"))
        self._switch_tree.setColumnWidth(0, 100)

    def initLayout(self):
        layout = qt.qvboxlayout()()
        layout.addWidget(self._switch_tree)
        self.setLayout(layout)

    def click_tree(self):
        i = self._switch_tree.currentItem()
        addr = i.text(0).strip()
        if not addr.startswith("0x"):
            addr = idaapi.get_name_ea(idc.BADADDR, str(addr))
        else:
            addr = addr[2:10]
            addr = int(addr, 16)
        idc.Jump(addr)
        return

    def load(self):
        """
        title = "Switch Jumps"
        #root = QtGui.QTreeWidgetItem(self, title)
        comment = COLSTR("; Double-click to follow", SCOLOR_BINPREF)
        #self.AddLine(comment)
        comment = COLSTR("; Hover for preview", idc.SCOLOR_BINPREF)
        #self.AddLine(comment)
        """
        self._switch_tree.clear()
        self._switch_tree.setColumnCount(2)
        self._switch_tree.clicked.connect(self.click_tree)
        self.find_all_switch_jumps()
        for func in sorted(self._switch_dict.keys()):
            func_node = qt.qtreewidgetitem()(self._switch_tree)
            func_node.setText(0, func)
            func_node.setText(1, "")
            for item in self._switch_dict[func]:
                node = qt.qtreewidgetitem()(func_node)
                addr = item[0]
                cases = item[1]
                address_element = "0x%08x" % addr
                node.setText(0, address_element)
                node.setText(1, "%04s" % cases)
                for c in item[2]:
                    cnode = qt.qtreewidgetitem()(node)
                    cnode.setText(0, c[0])
                    cnode.setText(1, c[2])
        return True

    def get_jlocs(self, sw):
        jlocs = []
        ncases = sw.ncases if sw.jcases == 0 else sw.jcases
        for i in range(ncases):
            addr = idc.Dword(sw.jumps+i*4)
            name = idaapi.get_name(idc.BADADDR, addr)
            comm = idc.GetCommentEx(idc.LocByName(name), 1)
            comm = comm[comm.find('case'):] if comm is not None and comm.startswith('jumptable') else comm
            jlocs.append((name, idc.LocByName(name), comm))
        return jlocs

    def find_all_switch_jumps(self):
        self._switch_dict = defaultdict(list)
        next_switch = idc.FindBinary(idc.MinEA(), idc.SEARCH_DOWN|idc.SEARCH_NEXT, "ff 24")
        while next_switch != idc.BADADDR:
            sw = idaapi.get_switch_info_ex(next_switch)
            if idc.GetMnem(next_switch).startswith("jmp") and sw:
                ic = self.get_jlocs(sw)
                self._switch_dict[idaapi.get_func_name(next_switch)].append((next_switch, sw.ncases, ic))
            next_switch = idc.FindBinary(idc.NextHead(next_switch), idc.SEARCH_DOWN|idc.SEARCH_NEXT, "ff 24")

    def getTacoTab(self):
        taco_tab = qt.qwidget()()
        layout = qt.qvboxlayout()()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
