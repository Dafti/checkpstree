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
        def printProcs(indent, pstree):
            for p in pstree:
                outfd.write("{}{}\n".format('.' * indent, p['pid']))
                printProcs(indent + 1, p['children'])
        printProcs(0, check_data['pstree'])


    def buildPsTree(self, pslist):

        def attachChild(child, pstree):
            for parent in pstree:
                if parent['pid'] == child['ppid']:
                    parent['children'].append(child)
                    return True
                else:
                    if attachChild(child, parent['children']):
                        return True
            return False

        def addPs(task, pstree):
            proc = {'pid': int(task.UniqueProcessId),
                    'ppid': int(task.InheritedFromUniqueProcessId),
                    'proc': task,
                    'children': []}
            for index, child in enumerate(pstree):
                if child['ppid'] == proc['pid']:
                    proc['children'].append(child)
                    del pstree[index]
            if not attachChild(proc, pstree):
                pstree.append(proc)

        pstree = []
        for task in pslist:
            addPs(task, pstree)
        return pstree


    def checking(self, pslist):
        pstree = self.buildPsTree(pslist)
        return {'pstree': pstree}
        

    @cache.CacheDecorator(lambda self: "tests/checkpstree/verbose={0}".format(self._config.VERBOSE))
    def calculate(self):
        psdict = pstree.PSTree.calculate(self)
        addr_space = utils.load_as(self._config)
        check_data = self.checking(tasks.pslist(addr_space))
        return { "pstree": psdict, "check": check_data }
