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

__version__ = "0.1"
__author__ = "arbor-jjones"

import idaapi

from PyQt5 import QtWidgets, QtGui, QtCore

import idataco.util.qt as qt

from idataco.widgets.imports import TacoImports
from idataco.widgets.loader import TacoLoader
from idataco.widgets.calls import TacoCalls
from idataco.widgets.byte_strings import TacoByteStrings
from idataco.widgets.interesting_xor import TacoInterestingXOR
from idataco.widgets.switch_jumps import TacoSwitchJumps
from idataco.widgets.signatures import TacoSignatures

import logging
log = logging.getLogger("taco")
log.setLevel('DEBUG')
handler = logging.StreamHandler()
# clear any existing handlers to avoid duplicate messages
log.handlers = []
handler.setFormatter(logging.Formatter("[%(asctime)s] [%(module)s] [%(levelname)s] %(funcName)s: %(message)s"))
log.addHandler(handler)

"""
IDA TACO is an IDA Pro Plugin designed to bring Cuckoo Sandbox-generated output into IDA Pro
to assist in reverse engineering malware as well as combining some commonly used tools into one UI
"""
class IDATaco(idaapi.PluginForm):

    ENABLED_WIDGETS = [
        TacoLoader,
        TacoCalls,
        TacoSignatures,
        TacoImports,
        TacoByteStrings,
        TacoInterestingXOR,
        TacoSwitchJumps
    ]

    def Show(self):
        return idaapi.PluginForm.Show(self, "T.A.C.O.", options=idaapi.PluginForm.FORM_PERSIST)

    def OnCreate(self, form):
        # Get parent widget

        self.parent = qt.formtowidget(self, form)
        self.calls = []
        self.call_categories = set()
        self.cuckoo_version = "Unknown"
        self.impts = []

        # Create tab control
        self.tabs = qt.qtabwidget()()
        self.tabs.setTabsClosable(False)

        self._widgets = {}

        # create
        for widget in self.ENABLED_WIDGETS:
            w = widget(self)
            self._widgets[widget.short_name] = w
            tab, tab_name = w.getTacoTab()
            self.tabs.addTab(tab, tab_name)

        layout = qt.qvboxlayout()()
        layout.addWidget(self.tabs)
        self.parent.setLayout(layout)
        self.loadNonCuckooTabs()

    def loadNonCuckooTabs(self):
        for widget_name, widget in self._widgets.iteritems():
            if not widget_name.startswith("cuckoo_"):
                log.debug("Loading Widget {}".format(widget_name))
                widget.load()

    def OnClose(self, form):
        global TacoForm
        del TacoForm

        log.debug("Closing")

    def Create(self):
        return True

    def jsonFileLoaded(self):
        self._widgets["cuckoo_loader"].loadProcTree()
        self._widgets["cuckoo_signatures"].load()

    def loadProcessData(self):
        selected = self._widgets["cuckoo_loader"].getSelectedItems()
        if len(selected) == 1:
            pid = int(selected[0].text(0))
            data = self.process_data[pid]
            self.impts = data["imports"]
            self.calls = data["calls"]
            del data

            # @TODO: Set a flag for tabs that need to be signaled on data load
            self._widgets["cuckoo_imports"].load()
            self._widgets["cuckoo_calls"].load()


def start():
    global TacoForm
    TacoForm = IDATaco()
    TacoForm.Show()

start()
