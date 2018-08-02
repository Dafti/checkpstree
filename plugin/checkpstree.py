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
# from volatility import renderers
# from volatility.renderers.basic import Address

import volatility.win32.tasks as tasks
import volatility.utils as utils
# import volatility.plugins.common as common
import volatility.cache as cache
# import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.pstree as pstree
import copy
import os.path
import json

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

        def printUniqueNames(testedEntries):
            self.table_header(outfd,
                    [("Name", "<50"),
                     ("Count", ">6"),
                     ("Pass", ">6")])
            for t in testedEntries:
                self.table_row(outfd,
                        t['name'],
                        t['count'],
                        'True' if t['pass'] else 'False')

        printProcs(0, check_data['pstree'])
        check = check_data['check']
        if 'unique_names' in check:
            printUniqueNames(check['unique_names'])


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


    def checkUniqueNames(self, pstree):
        def countOcurrences(name, pstree):
            count = 0
            for ps in pstree:
                if str(ps['proc'].ImageFileName) == name:
                    count = count + 1
                count = count + countOcurrences(name, ps['children'])
            return count

        report = []
        for name in self._check_config['unique_names']:
            count = countOcurrences(name, pstree)
            ret = {'name': name,
                    'count': count,
                    'pass': True if count <= 1 else False}
            report.append(ret)
        return report


    def checking(self, pslist):
        pstree = self.buildPsTree(pslist)
        check = {}
        if self._check_config['unique_names']:
            report = self.checkUniqueNames(pstree)
            check['unique_names'] = report
        return {'pstree': pstree, 'check': check}


    # Check the configuration files
    # If no configuration was provided we try to load a configuration file from
    # <plugin_path>/checkpstree_configs/<profile>.json
    # profile being the value in self._config.PROFILE
    # If the user specifies another configuration file in self._config.CONFIG
    # then the user specified file is loaded.
    def checkConfig(self):
        config_filename = self._config.CONFIG
        if config_filename is None:
            profile = self._config.PROFILE + ".json"
            path = self._config.PLUGINS
            config_filename = os.path.join(path, "checkpstree_configs", profile)
        # check config file exists and it's a file
        if not os.path.exists(config_filename):
            debug.error("Configuration file '{}' does not exist".format(
                config_filename))
        if not os.path.isfile(config_filename):
            debug.error("Configuration filename '{}' is not a regular file".format(
                config_filename))
        # open configuration file and parse contents
        try:
            config_file = open(config_filename)
        except:
            debug.error("Couldn't open configuration file '{}'".format(
                config_filename))
        try:
            config = json.load(config_file)
        except:
            debug.error("Couldn't load json configuration from '{}'".format(
                config_filename))
        # TODO: could be nice to make some checking on the configuration format
        #       to verify that it has the supported fields and so on
        self._check_config = config['config']


    @cache.CacheDecorator(lambda self: "tests/checkpstree/verbose={0}".format(self._config.VERBOSE))
    def calculate(self):
        self.checkConfig()
        psdict = pstree.PSTree.calculate(self)
        addr_space = utils.load_as(self._config)
        check_data = self.checking(tasks.pslist(addr_space))
        return { "pstree": psdict, "check": check_data }
