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

"""
Base class all tabs in TACO should sub-class for consistency
"""


class TacoTabWidget(qt.qwidget()):
    name = ""
    short_name = ""

    def __init__(self, parent):
        qt.qwidget().__init__(self)
        qt.qtablewidget()()
        self.parent = parent
        self.initVars()
        self.initLayout()

    """
    Responsible for initializing any class specific variables, allowed to do nothing
    """
    def initVars(self):
        pass

    """
    Initializes the per-widget tab layout
    """
    def initLayout(self):
        raise Exception("Widgets must override this")

    """
    Initialize the tab itself

    @return Tuple that contains QWidget consisting of tab layout + data and name of tab
    """
    def getTacoTab(self):
        raise Exception("Widgets must override this")


    """
    Responsible for loading data into the TacoTab
    """
    def load(self):
        raise Exception("Widgets must override this")