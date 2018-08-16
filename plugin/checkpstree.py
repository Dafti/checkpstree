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
import os.path
import json
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.obj as obj
import volatility.debug as debug
from volatility.renderers.basic import Address, Hex
import volatility.plugins.vadinfo as vadinfo

#pylint: disable-msg=C0111

class CheckPSTree(common.AbstractWindowsCommand):
    """Print process list as a tree and perform check on common anomalies"""
    # Declare meta information associated with this plugin
    meta_info = {
        'author': ['Toni', 'CFX', 'Eric Jouenne', 'Daniel Gracia Perez'],
        'copyright': 'Copyright (c) 2018 ' +
                     'Toni, ' +
                     'CFX, ' +
                     'Eric Jouenne and ' +
                     'Daniel Gracia Perez',
        'contact': 'daniel.gracia-perez@cfa-afti.fr',
        'license': 'GNU General Public License 2.0',
        'url': 'https://github.com',
        'version': '1.0'}

    text_sort_column = "pid"

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option(
            'CONFIG', short_option='c', default=None,
            help='Full path to checkpstree configuration file',
            action='store', type='str')
        self._check_config = {}

    def render_text(self, outfd, data):

        def sort_processes(psdict):
            def add_processes(ps_sorted, ps_level, ppid, level):
                pids = [ps['pid'] for ps in psdict.values() if ps['ppid'] == ppid]
                for pid in pids:
                    ps_sorted.append(pid)
                    ps_level.append(level)
                    add_processes(ps_sorted, ps_level, pid, level + 1)

            ps_sorted = []
            ps_level = []
            while len(ps_sorted) != len(psdict):
                roots = [ps['pid'] for ps in psdict.values() if ps['ppid'] not in psdict.keys() and ps['pid'] not in ps_sorted]
                if not roots:
                    debug.warning("No root found")
                    break
                root = roots[0]
                ps_sorted.append(root)
                ps_level.append(0)
                add_processes(ps_sorted, ps_level, root, 1)
            return zip(ps_sorted, ps_level)

        def print_pstree(psdict):
            outfd.write("PSTree\n")
            ps_sorted = sort_processes(psdict)
            self.table_header(outfd,
                              [("Level", "<8"),
                               ("pid", ">6"),
                               ("ppid", ">6"),
                               ("Name", "<20"),
                               ("U", "<2"),
                               ("NC", "<2"),
                               ("NP", "<2"),
                               ("R", "<2"),
                               ("P", "<2"),
                               ("S", "<2")])
            for (pid, level) in ps_sorted:
                unique_names = ''
                if 'unique_names' in psdict[pid]['check']:
                    unique_names = 'T' if psdict[pid]['check']['unique_names'] else 'F'
                no_children = ''
                if 'no_children' in psdict[pid]['check']:
                    no_children = 'T' if psdict[pid]['check']['no_children'] else 'F'
                no_parent = ''
                if 'no_parent' in psdict[pid]['check']:
                    no_parent = 'T' if psdict[pid]['check']['no_parent'] else 'F'
                reference_parents = ''
                if 'reference_parents' in psdict[pid]['check']:
                    reference_parents = 'T' if psdict[pid]['check']['reference_parents'] else 'F'
                path = ''
                if 'path' in psdict[pid]['check']:
                    path = 'T' if psdict[pid]['check']['path'] else 'F'
                static_pid = ''
                if 'static_pid' in psdict[pid]['check']:
                    static_pid = 'T' if psdict[pid]['check']['static_pid'] else 'F'
                self.table_row(outfd,
                               '.' * level,
                               pid,
                               psdict[pid]['ppid'],
                               psdict[pid]['name'],
                               unique_names,
                               no_children,
                               no_parent,
                               reference_parents,
                               path,
                               static_pid)
            outfd.write("\n")

        def print_unique_names(entries, psdict):
            self.table_header(outfd,
                              [("Name", "<50"),
                               ("Count", ">6"),
                               ("Pass", ">6")])
            for entry in entries:
                count = len([x for x in psdict.values() if x['name'] == entry['name']])
                self.table_row(outfd,
                               entry['name'],
                               count,
                               'True' if entry['check']['unique_names'] else 'False')

        def print_reference_parents(entries, psdict):
            self.table_header(outfd,
                              [('Name', '<50'),
                               ('pid', '>6'),
                               ('Parent', '<50'),
                               ('ppid', '>6'),
                               ('Pass', '>6'),
                               ('Expected Parent', '<50')])
            ref_parents = self._check_config['reference_parents']
            for entry in entries:
                expected = ref_parents[entry['name']]
                self.table_row(outfd,
                               entry['name'],
                               entry['pid'],
                               psdict[entry['ppid']]['name'],
                               entry['ppid'],
                               'True' if entry['check']['reference_parents'] else 'False',
                               expected)

        def print_path(entries, psdict):
            self.table_header(outfd,
                              [('pid', '>6'),
                               ('Name', '<20'),
                               ('Path', '<40'),
                               ('Pass', '>6'),
                               ('Expected Path', '<40')])
            for entry in entries:
                expected = self._check_config['path'][entry['name']]
                self.table_row(outfd,
                               entry['pid'],
                               entry['name'],
                               entry['path'],
                               'True' if entry['check']['path'] else 'False',
                               expected)

        def print_no_children(entries, psdict):
            self.table_header(outfd,
                              [('pid', '>6'),
                               ('Name', '<20'),
                               ('Pass', '>6'),
                               ('pid_child', '>9'),
                               ('Name_child', '<20')])
            for entry in entries:
                if not entry['check']['no_children']:
                    children = [x['pid'] for x in psdict.values() if x['ppid'] == entry['pid']]
                    for pid in children:
                        self.table_row(outfd,
                                       entry['pid'],
                                       entry['name'],
                                       'False',
                                       pid,
                                       psdict[pid]['name'])
                else:
                    self.table_row(outfd,
                                   entry['pid'],
                                   entry['name'],
                                   'True',
                                   '',
                                   '')

        def print_static_pid(entries, psdict):
            self.table_header(outfd,
                              [('pid', '>6'),
                               ('Name', '<20'),
                               ('Pass', '>6'),
                               ('Expected pid', '>12')])
            for entry in entries:
                expected = self._check_config['static_pid'][entry['name']]
                self.table_row(outfd,
                               entry['pid'],
                               entry['name'],
                               'True' if entry['check']['static_pid'] else 'False',
                               expected)

        def print_check(print_func, check_name, psdict):
            outfd.write("{} Check\n".format(check_name))
            entries = [ps for ps in psdict.values() if 'check' in ps and check_name in ps['check']]
            if not entries:
                outfd.write("> No suspicious entries found (nothing inspected)\n")
            else:
                if self._config.VERBOSE:
                    print_func(entries, psdict)
                else:
                    suspicious_entries = [ps for ps in entries if not ps['check'][check_name]]
                    if not suspicious_entries:
                        outfd.write("> No suspicious entries found\n")
                    else:
                        print_func(suspicious_entries, psdict)
            outfd.write("\n")

        psdict = data['psdict']
        outfd.write("""
===============================================================================
CheckPSTree analysis report

""")
        print_pstree(psdict)
        print_funcs = {'unique_names': print_unique_names,
                       'no_children': print_no_children,
                       'reference_parents': print_reference_parents,
                       'path': print_path,
                       'static_pid': print_static_pid}
        for key in self._check_config.keys():
            if key in print_funcs.keys():
                print_check(print_funcs[key], key, psdict)
        outfd.write("""
===============================================================================

""")

    def check_unique_names(self, psdict):
        check_entries = self._check_config['unique_names']
        for name in check_entries:
            pids = [x['pid'] for x in psdict.values() if x['name'] == name]
            if len(pids) == 1:
                psdict[pids[0]]['check']['unique_names'] = True
            else:
                if len(pids) > 1:
                    for pid in pids:
                        psdict[pid]['check']['unique_names'] = False

    def check_no_children(self, psdict):
        check_entries = self._check_config['no_children']
        for ps in psdict.values():
            if ps['name'] in check_entries:
                children = [x['pid'] for x in psdict.values() if x['ppid'] == ps['pid']]
                ps['check']['no_children'] = not children

    def check_no_parent(self, psdict):
        check_entries = self._check_config['no_parent']
        for ps in psdict.values():
            if ps['name'] in check_entries:
                parent = [x['pid'] for x in psdict.values() if x['pid'] == ps['ppid']]
                ps['check']['no_parent'] = not parent

    def check_reference_parents(self, psdict):
        check_entries = self._check_config['reference_parents']
        for ps in psdict.values():
            if ps['name'] in check_entries:
                check_pass = psdict[ps['ppid']]['name'] == check_entries[ps['name']]
                ps['check']['reference_parents'] = check_pass

    def check_path(self, psdict):
        check_entries = self._check_config['path']
        for ps in psdict.values():
            if ps['name'] in check_entries:
                path = ps['path'].lower() if ps['path'] else ""
                expected_path = check_entries[ps['name']].lower()
                ps['check']['path'] = path == expected_path

    def check_static_pid(self, psdict):
        check_entries = self._check_config['static_pid']
        for ps in psdict.values():
            if ps['name'] in check_entries.keys():
                check_pass = ps['pid'] == int(check_entries[ps['name']])
                ps['check']['static_pid'] = check_pass

    # Perform plugin checks. Currently it includes:
    # - unique_names
    # - no_children
    # - no_parent
    # - reference_parents
    # - path
    # - static_pid
    def checking(self, psdict):
        # For every check in the configuration perform the correspondent check.
        check_funcs = {'unique_names': self.check_unique_names,
                       'no_children': self.check_no_children,
                       'no_parent': self.check_no_parent,
                       'reference_parents': self.check_reference_parents,
                       'path': self.check_path,
                       'static_pid': self.check_static_pid}
        for key in self._check_config.keys():
            if key in check_funcs.keys():
                check_funcs[key](psdict)

    # Check the configuration files
    # If no configuration was provided we try to load a configuration file from
    # <plugin_path>/checkpstree_configs/<profile>.json
    # profile being the value in self._config.PROFILE
    # If the user specifies another configuration file in self._config.CONFIG
    # then the user specified file is loaded.
    def check_config(self):
        config_filename = self._config.CONFIG
        if config_filename is None:
            profile = self._config.PROFILE + ".json"
            path = self._config.PLUGINS
            config_filename = os.path.join(path,
                                           "checkpstree_configs",
                                           profile)
        # check config file exists and it's a file
        if not os.path.exists(config_filename):
            debug.error("Configuration file '{}' does not exist".format(
                config_filename))
        if not os.path.isfile(config_filename):
            debug.error(
                "Configuration filename '{}' is not a regular file".format(
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

    def build_psdict(self):
        addr_space = utils.load_as(self._config)
        pslist = tasks.pslist(addr_space)
        psdict = {}
        for ps in pslist:
            proc = {'pid': int(ps.UniqueProcessId),
                    'ppid': int(ps.InheritedFromUniqueProcessId),
                    'name': str(ps.ImageFileName),
                    'ctime': str(ps.CreateTime),
                    'audit': str(ps.SeAuditProcessCreationInfo.ImageFileName.Name or ''),
                    'cmd': None,
                    'path': None,
                    'check': {}}
            process_params = ps.Peb.ProcessParameters
            if process_params:
                proc['cmd'] = str(process_params.CommandLine)
                proc['path'] = str(process_params.ImagePathName)
            # TODO: check that the pid doesn't already exist
            psdict[proc['pid']] = proc
        return psdict

    @cache.CacheDecorator(lambda self: "tests/checkpstree/verbose={0}".format(
        self._config.VERBOSE))
    def calculate(self):
        # Check the plugin configuration
        self.check_config()
        # Get a dictionary of all the processes indexed by pid
        psdict = self.build_psdict()
        # Perform plugin checks
        check_reports = self.checking(psdict)
        # Return output data (data that can be printed in the console)
        return {"psdict": psdict, "check": check_reports}
