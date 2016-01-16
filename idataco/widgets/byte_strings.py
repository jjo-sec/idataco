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
import ctypes

import idataco.util.qt as qt
from . import TacoTabWidget

import idc
import idautils
import idaapi

import logging

log = logging.getLogger("taco.widgets")


class TacoByteStrings(TacoTabWidget):

    name = "Byte Strings"
    short_name = "byte_strings"
    description = """ Attempt to find all byte / stack strings in a selected executable. """

    def initVars(self):
        self.byte_strings = {}
        self._bytestring_table = qt.qtablewidget()()
        self._bytestring_table.setRowCount(1)
        self._bytestring_table.setColumnCount(3)
        self._bytestring_table.setHorizontalHeaderLabels(("Address", "Function", "String"))
        self._clipboard = qt.qclipboard()

    def initLayout(self):
        layout = qt.qvboxlayout()()
        layout.addWidget(self._bytestring_table)
        self.setLayout(layout)

    def click_row(self):
        i = self._bytestring_table.item(self._bytestring_table.currentRow(), 0)
        bstr = self._bytestring_table.item(self._bytestring_table.currentRow(), 2)
        addr = i.text().strip()
        bstr = bstr.text()
        if not addr.startswith("0x"):
            addr = idaapi.get_name_ea(idc.BADADDR, str(addr))
        else:
            addr = addr[2:10]
            addr = int(addr, 16)
        idc.Jump(addr)
        self._clipboard.setText(bstr)


    def load(self):
        self._bytestring_table.clear()
        self._bytestring_table.setColumnCount(3)
        self._bytestring_table.setHorizontalHeaderLabels(("Address", "Function", "String"))
        self._bytestring_table.itemDoubleClicked.connect(self.click_row)
        self.find_byte_strings()
        self._bytestring_table.setRowCount(len(self.byte_strings.keys()))
        row = 0
        for addr, bstr in self.byte_strings.items():
            self._bytestring_table.setItem(row, 0, qt.qtablewidgetitem()(addr))
            self._bytestring_table.setItem(row, 1, qt.qtablewidgetitem()(idaapi.get_func_name(int(addr[2:], 16))))
            self._bytestring_table.setItem(row, 2, qt.qtablewidgetitem()(bstr))
            self._bytestring_table.resizeRowToContents(row)
            row += 1
        self._bytestring_table.setSortingEnabled(True)
        self._bytestring_table.resizeRowsToContents()
        self._bytestring_table.resizeColumnsToContents()



    def find_byte_strings(self):
        for f in idautils.Functions():
            func = idaapi.get_func(f)
            chr_vals = {}
            eightbit = {}
            for head in idautils.Heads(func.startEA,func.endEA):
                if idc.GetMnem(head) == "mov":
                    if re.match('[abcd]l', idc.GetOpnd(head, 0)) and idc.GetOpType(head,1) == idc.o_imm and ((idc.GetOperandValue(head,1) >= 0x20 and idc.GetOperandValue(head,1) <= 0x7f) or idc.GetOperandValue(head,1) in [0xd,0xa]):
                        eightbit[idc.GetOpnd(head,0)] = idc.GetOperandValue(head,1)
                    if (idc.GetOpnd(head,0).startswith('byte ptr') or idc.GetOpnd(head,0).startswith('[e')) and idc.GetOpType(head,1) == idc.o_imm and  ((idc.GetOperandValue(head,1) >= 0x20 and idc.GetOperandValue(head,1) <= 0x7f) or idc.GetOperandValue(head,1) in [0xd,0xa]):
                        reg = idc.GetOpnd(head,0)
                        reg = reg[reg.find('['):]
                        if reg.count('+') == 0: offset = 0
                        else:
                            #ops = reg.split('+')
                            reg = reg[1:4]
                            offset = ctypes.c_int32(idc.GetOperandValue(head, 0)).value
                            #reg_base = 0
                            #if len(ops) > 2 and ops[1].endswith('h'):
                            #    reg_base = int(ops[1][:-1], 16)
                            #offset -= reg_base
                        if reg not in chr_vals: chr_vals[reg] = {}
                        chr_vals[reg][offset] = (head, chr(idc.GetOperandValue(head, 1)))
                    elif (idc.GetOpnd(head, 0).startswith('byte ptr') or idc.GetOpnd(head, 0).startswith('[e')) and idc.GetOpType(head, 1) == idc.o_reg and idc.GetOpnd(head, 1) in eightbit:
                        reg = idc.GetOpnd(head, 0)
                        reg = reg[reg.find('['):]
                        if reg.count('+') == 0:
                            offset = 0
                        else:
                            #ops = reg.split('+')
                            #reg = reg[:reg.find('+')]+']'
                            reg = reg[1:4]

                            offset = ctypes.c_int32(idc.GetOperandValue(head, 0)).value
                            #reg_base = 0
                            #if len(ops) > 2 and ops[1].endswith('h'):
                            #    reg_base = int(ops[1][:-1],16)
                            #offset -= reg_base

                        if reg not in chr_vals:
                            chr_vals[reg] = {}
                        chr_vals[reg][offset] = (head, chr(eightbit[idc.GetOpnd(head, 1)]))
                    elif idc.GetOpnd(head, 0).startswith('word ptr') and idc.GetOpType(head, 1) == idc.o_imm:
                        val = idc.GetOperandValue(head, 1)
                        chrs = "{:04x}".format(val).decode('hex')[::-1]
                        reg = idc.GetOpnd(head, 0)
                        reg = reg[reg.find('[')+1:]
                        reg = reg[:3]
                        offset = ctypes.c_int32(idc.GetOperandValue(head, 0)).value
                        if reg not in chr_vals:
                            chr_vals[reg] = {}
                        for c in chrs:
                            chr_vals[reg][offset] = (head, c)
                            offset += 1
                    elif idc.GetOpType(head, 1) == idc.o_imm:
                        val = idc.GetOperandValue(head, 1)
                        chrs = "{:08x}".format(val).decode('hex')[::-1]
                        #if val < 0xffff:
                        #    continue
                        badchar = False
                        for c in chrs:
                            if ord(c) not in [0x0, 0xa, 0xd] and (ord(c) < 0x20 or ord(c) > 0x80):
                                badchar = True
                                break
                        if badchar:
                            continue
                        reg = idc.GetOpnd(head, 0)
                        reg = reg[reg.find('[')+1:]
                        reg = reg[:3]
                        offset = ctypes.c_int32(idc.GetOperandValue(head, 0)).value
                        if reg not in chr_vals:
                            chr_vals[reg] = {}
                        for c in chrs:
                            chr_vals[reg][offset] = (head, c)
                            offset += 1

            for reg, c_v in chr_vals.items():
                keys = c_v.keys()
                keys.sort()
                last = None
                s = ""
                offset = 0
                for o in keys:
                    if last is None:
                        addr = c_v[o][0]
                        offset = o
                        s = c_v[o][1]
                    elif last + 1 == o and c_v[o][1] != '\x00':
                        s += c_v[o][1]
                    else:
                        if s != "" and len(s) >= 5:
                            self.byte_strings["0x%X" % addr] = s
                            func = idaapi.get_func(addr)
                            if offset > 0:
                                s = ""
                                continue

                        s = c_v[o][1]
                        offset = o
                        addr = c_v[o][0]
                    last = o
                if s != "" and len(s) >= 5:
                    self.byte_strings["0x%X" % addr] = s
                    func = idaapi.get_func(addr)

    def getTacoTab(self):
        taco_tab = qt.qwidget()()
        layout = qt.qvboxlayout()()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
