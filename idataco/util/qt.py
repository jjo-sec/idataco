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
import idaapi

if re.match("^6.[0-8]$", idaapi.get_kernel_version()):
    from PySide import QtGui, QtCore


    def qtcore():
        return QtCore

    def formtowidget(pluginform, form):
        return pluginform.FormToPySideWidget(form)

    def qabstractitemview():
        return QtGui.QAbstractItemView

    def qwidget():
        return QtGui.QWidget

    def qtabwidget():
        return QtGui.QTabWidget

    def qvboxlayout():
        return QtGui.QVBoxLayout

    def qhboxlayout():
        return QtGui.QHBoxLayout

    def qtablewidget():
        return QtGui.QTableWidget

    def qaction():
        return QtGui.QAction

    def qtablewidgetitem():
        return QtGui.QTableWidgetItem

    def qclipboard():
        return QtGui.QClipboard()

    def qcolor():
        return QtGui.QColor

    def qcolordialog():
        return QtGui.QColorDialog

    def qpushbutton():
        return QtGui.QPushButton

    def qlabel():
        return QtGui.QLabel

    def qlineedit():
        return QtGui.QLineEdit

    def qcheckbox():
        return QtGui.QCheckBox

    def qtreewidget():
        return QtGui.QTreeWidget

    def qtreewidgetitem():
        return QtGui.QTreeWidgetItem

    def qfiledialog():
        return QtGui.QFileDialog

else:
    from PyQt5 import QtGui, QtWidgets, QtCore

    qt = "qt5"

    def qtcore():
        return QtCore

    def qabstractitemview():
        return QtWidgets.QAbstractItemView

    def formtowidget(pluginform, form):
        return pluginform.FormToPyQtWidget(form)

    def qwidget():
        return QtWidgets.QWidget

    def qtabwidget():
        return QtWidgets.QTabWidget

    def qvboxlayout():
        return QtWidgets.QVBoxLayout

    def qhboxlayout():
        return QtWidgets.QHBoxLayout

    def qtablewidget():
        return QtWidgets.QTableWidget

    def qaction():
        return QtWidgets.QAction

    def qtablewidgetitem():
        return QtWidgets.QTableWidgetItem

    def qclipboard():
        return QtWidgets.QApplication.clipboard()

    def qcolor():
        return QtGui.QColor

    def qcolordialog():
        return QtWidgets.QColorDialog

    def qpushbutton():
        return QtWidgets.QPushButton

    def qlabel():
        return QtWidgets.QLabel

    def qlineedit():
        return QtWidgets.QLineEdit

    def qcheckbox():
        return QtWidgets.QCheckBox

    def qtreewidget():
        return QtWidgets.QTreeWidget

    def qtreewidgetitem():
        return QtWidgets.QTreeWidgetItem

    def qfiledialog():
        return QtWidgets.QFileDialog