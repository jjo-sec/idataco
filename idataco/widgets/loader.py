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
import json

import idataco.util.qt as qt
from . import TacoTabWidget

import logging

log = logging.getLogger("taco")

class TacoLoader(TacoTabWidget):

    name = "Cuckoo Loader"
    short_name = "cuckoo_loader"
    description = """ Basic JSON File and Process Data Loader """

    def initVars(self):
        self._fpath = qt.qlineedit()()
        self._fpath.setMaxLength(128)

        self._proc_tree = qt.qtreewidget()()
        self._proc_tree.setColumnCount(2)
        self._proc_tree.setHeaderLabels(("PID", "ProcName"))
        self._proc_tree.setColumnWidth(0, 100)

    def initLayout(self):
        loader_vlayout = qt.qvboxlayout()()
        loader_hlayout = qt.qhboxlayout()()
        loader_hlayout.addWidget(qt.qlabel()("JSON File"))
        b = qt.qpushbutton()("Open File")
        b1 = qt.qpushbutton()("Process File")
        b.clicked.connect(self.getFileName)
        b1.clicked.connect(self.loadJsonFile)
        loader_hlayout.addWidget(self._fpath)
        loader_hlayout.addWidget(b)
        loader_hlayout.addWidget(b1)
        loader_vlayout.addLayout(loader_hlayout)
        #loader_hlayout2 = QtGui.QHBoxLayout()
        b2 = qt.qpushbutton()("Load Data for Selected Process")
        b2.clicked.connect(self.parent.loadProcessData)
        loader_vlayout.addWidget(b2)
        loader_vlayout.addWidget(self._proc_tree)
        self.setLayout(loader_vlayout)

    def getSelectedItems(self):
        return self._proc_tree.selectedItems()

    def loadJsonFile(self):
        with open(self._fpath.text()) as f:
            data = f.read()
            self._parseJsonFile(json.loads(data))
        self.parent.jsonFileLoaded()

    def addChildren(self, parentWidget, children):
        if self.parent.cuckoo_version.startswith("1."):
            for child in children:
                node = qt.qtreewidgetitem()(parentWidget)
                node.setText(0, "{}".format(child['pid']))
                node.setText(1, child['name'])
                self.addChildren(node, child['children'])
                self._proc_tree.expandItem(node)
        else:
            for child in children:
                node = qt.qtreewidgetitem()(parentWidget)
                node.setText(0, "{}".format(child['pid']))
                node.setText(1, child['process_name'])
                self.addChildren(node, child['children'])
                self._proc_tree.expandItem(node)

    def loadProcTree(self):
        self._proc_tree.clear()
        self._proc_tree.setColumnCount(2)
        self._proc_tree.setHeaderLabels(("PID", "ProcName"))
        self._proc_tree.setColumnWidth(0, 100)
        if self.parent.cuckoo_version.startswith("1."):
            for process in self.parent.process_tree:
                node = qt.qtreewidgetitem()(self._proc_tree)
                node.setText(0, "{}".format(process["pid"]))
                node.setText(1, process["name"])
                self.addChildren(node, process["children"])
                self._proc_tree.expandItem(node)
        else:
            for process in self.parent.process_tree:
                node = qt.qtreewidgetitem()(self._proc_tree)
                node.setText(0, "{}".format(process["pid"]))
                node.setText(1, process["process_name"])
                self.addChildren(node, process["children"])
                self._proc_tree.expandItem(node)

    def _parseJsonFile(self, json_data):
        _process_data = {}
        self.parent.cuckoo_version = json_data["info"].get("version", "Unknown")
        self.parent.call_categories = set()
        for proc in json_data["behavior"]["processes"]:
            ppid = proc["ppid"] if self.parent.cuckoo_version.startswith("2.0") else proc["parent_id"]
            pid = proc["pid"] if self.parent.cuckoo_version.startswith("2.0") else proc["process_id"]
            _process_data[pid] = {"process_name": proc["process_name"],
                                  "parent_id": ppid,
                                  "imports": [],
                                  "network": [],
                                  "calls": []
                                  }
            handles = {}
            exe_name = idc.GetInputFile().split(".")[0]
            for call in proc["calls"]:
                self.parent.call_categories.add(call["category"])
                if self.parent.cuckoo_version.startswith("1."):
                    args = dict([(x["name"], x["value"]) for x in call["arguments"]])
                    call["arguments"] = args
                else:
                    args = call["arguments"]
                _process_data[pid]["calls"].append(call)
                if call["api"] in ["LdrGetDllHandle", "LdrLoadDll"]:
                    if self.parent.cuckoo_version.startswith("1."):
                        if call["api"] == "LdrGetDllHandle" and args["ModuleHandle"] != "0x00000000":
                            handles[args["ModuleHandle"]] = args["FileName"]
                        elif call["api"] == "LdrLoadDll" and call["return"] == "0x00000000":
                            handles[args["BaseAddress"]] = args["FileName"]
                    # cuckoo 2.0
                    else:
                        if call["api"] == "LdrGetDllHandle" and args["module_address"] != "0x00000000":
                            handles[args["module_address"]] = args["module_name"]
                        elif call["api"] == "LdrLoadDll" and call["return_value"] == 0:
                            handles[args["module_address"]] = args["module_name"]
                elif call["api"] == "LdrGetProcedureAddress":
                    if args.get("FunctionName", None):
                        impt_type = "Unknown"
                        if "caller" in call:
                            impt_type = "Indirect"
                            addr = idc.PrevHead(int(call["caller"], 16))
                            if addr != idc.BADADDR:
                                # if the call is direct to a register or stack variable
                                # assume that this is intentional obfuscation of GetProcAddress
                                if idc.GetMnem(addr) == "call" and \
                                    (re.match("^e[abcds][ipx]$", idc.GetOpnd(addr, 0)) \
                                     or idc.GetOpnd(addr, 0).endswith("GetProcAddress") \
                                     or idc.GetOpnd(addr, 0).startswith(("ds:dword", "dword ptr", "[e"))):
                                    impt_type = "Dynamic"
                            _process_data[pid]["imports"].append({"addr": "0x{:08X}".format(addr),
                                                                  "dll": handles.get(args["ModuleHandle"], args["ModuleName"]),
                                                                  "proc_name": args["FunctionName"],
                                                                  "proc_address": args["FunctionAddress"],
                                                                  "type": impt_type
                                                                  }
                                                                 )
                        elif "stacktrace" in call and call["stacktrace"]:
                            # handle case where injected code below ImageBase so don"t get exe_name prepended
                            if call["stackstrace"][0].startswith("GetProcAddress") and \
                               call["stackstrace"][0].count(" ") == 2 and (call["stacktrace"][1].startswith(exe_name) or \
                               call["stackstrace"][0].count(" ") == 0):
                                impt_type = "Dynamic"
                                addr = int(call["stackstrace"][1].split(" @ ")[-1], 16)
                            elif call["stacktrace"][0].startswith(exe_name):
                                impt_type = "Dynamic"
                                addr = int(call["stacktrace"][0].split(" @ ")[-1], 16)
                            else:
                                for frm in call["stacktrace"]:
                                    if frm.startswith(exe_name) or frm.count(" ") == 0:
                                        addr = int(call["stacktrace"][0].split(" @ ")[-1], 16)
                                        break
                            _process_data[pid]["imports"].append({
                                                                  "addr": "0x{:08X}".format(addr),
                                                                  "dll": handles.get(args["module_address"], args["module_address"]),
                                                                  "proc_name": args["function_name"],
                                                                  "proc_address": args["function_address"],
                                                                  "type": impt_type
                                                                  }
                                                                 )
        self.parent.signatures = json_data["signatures"]
        self.parent.process_data = _process_data
        self.parent.process_tree = json_data["behavior"]["processtree"]
        del json_data

    def getFileName(self):
        fileName = qt.qfiledialog().getOpenFileName(self, "Open JSON", None, "JSON Files (*.json)")
        if fileName and fileName[0]:
            self._fpath.setText(fileName[0])

    def getTacoTab(self):
        taco_tab = qt.qwidget()()
        layout = qt.qvboxlayout()()
        layout.addWidget(self)
        taco_tab.setLayout(layout)
        return taco_tab, self.name
