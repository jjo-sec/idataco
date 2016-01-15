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

import idataco.util.qt as qt
from . import TacoTabWidget

import logging

log = logging.getLogger("taco.widgets")


class TacoSignatures(TacoTabWidget):

    name = "Cuckoo Signatures"
    short_name = "cuckoo_signatures"
    description = """ Simple display of signatures detected by Cuckoo Sandbox """

    def initVars(self):
        self._signature_table = qt.qtablewidget()()
        self._signature_table.setRowCount(0)
        self._signature_table.setColumnCount(3)
        self._signature_table.setHorizontalHeaderLabels(["Signature","Information","Severity"])

    def initLayout(self):
        sig_table_layout = qt.qvboxlayout()()
        sig_table_layout.addWidget(self._signature_table)
        self.setLayout(sig_table_layout)

    def load(self):
        self._signature_table.clear()
        self._signature_table.setHorizontalHeaderLabels(["Signature", "Information", "Severity"])
        self._signature_table.setRowCount(len(self.parent.signatures))
        row = 0
        for sig in self.parent.signatures:
            d = {}
            for x in sig["data"]: d.update(x)
            data = "\n".join(["{}: {}".format(k, v) for k, v in d.iteritems()])
            sev = "Severity: {severity}\nConfidence: {confidence}\nWeight: {weight}".format(**sig)
            self._signature_table.setItem(row, 0, qt.qtablewidgetitem()(sig["description"]))
            self._signature_table.setItem(row, 1, qt.qtablewidgetitem()(data))
            self._signature_table.setItem(row, 2, qt.qtablewidgetitem()(sev))
            row += 1

        self._signature_table.resizeRowsToContents()
        self._signature_table.resizeColumnsToContents()
        self._signature_table.setSortingEnabled(True)

    def getTacoTab(self):
        taco_tab = qt.qwidget()()
        layout = qt.qhboxlayout()()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
