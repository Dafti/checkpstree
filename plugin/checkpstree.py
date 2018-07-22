# Volatility
#
# Authors
# Toni
# CFX
# Eric
# Daniel Gracia Perez <daniel.gracia-perez@cfa-afti.fr>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""checkpstree example file"""
from volatility import renderers
from volatility.renderers.basic import Address

import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.pstree as pstree
import copy

#pylint: disable-msg=C0111

class CheckPSTree(pstree.PSTree):
    """Print process list as a tree and perform check on common anomalies"""
    # Declare meta information associated with this plugin
    meta_info = {
        'author': [ 'Toni', 'CFX', 'Eric Jouenne', 'Daniel Gracia Perez' ],
        'copyright': 'Copyright (c) 2018 Toni, CFX, Eric Jouenne and Daniel Gracia Perez',
        'contact': 'daniel.gracia-perez@cfa-afti.fr',
        'license': 'GNU General Public License 2.0',
        'url': 'https://github.com',
        'version': '1.0'}

    text_sort_column = "Pid"

    def __init__(self, config, *args, **kwargs):
        pstree.PSTree.__init__(self, config, *args, **kwargs)
        config.add_option('CONFIG', short_option='c', default=None,
                help = 'Full path to checkpstree configuration file',
                action='store', type='str')

    def render_text(self, outfd, data):
        pstree.PSTree.render_text(self, outfd, data["pstree"])
        check_data = data["check"]
        outfd.write("""
===============================================================================
Analysis report
""")
        outfd.write(str(check_data))
        self.table_header(outfd,
                [("test", "<5"),
                 ("test2", ">6"),
                 ("test3", "")])
        self.table_row(outfd,
            "col1", "col2", "col3")


    def buildPTree(self, pdict, ptree = []):
        for (pid, proc) in pdict.items():
            print("PPID {} - PID {}\n".format(proc.InheritedFromUniqueProcessId, pid))
            if len(ptree) == 0:
                ptree.append({pid:proc})
            else:
                ptree.append({pid:proc})
            del pdict[pid]
        return ptree

#         def buildPChildTree(parent):
#             return { "parent": parent, "childreen": [child_list] }
# 
#         roots = self.findPRoots(pstree_data)
#         ptree = []
#         for root in roots:
#             ptree.add(buildPChildTree(pstree_data, root))
#         return ptree


    def checking(self, psdict):
        pstree = self.buildPTree(psdict)
        return pstree
        

    @cache.CacheDecorator(lambda self: "tests/checkpstree/verbose={0}".format(self._config.VERBOSE))
    def calculate(self):
        psdict = pstree.PSTree.calculate(self)
        # TODO: check why deepcopy doesn't work
        # check_data = self.checking(copy.deepcopy(psdict))
        check_data = self.checking(pstree.PSTree.calculate(self))
        return { "pstree": psdict, "check": check_data }
