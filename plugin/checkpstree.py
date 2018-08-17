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
import difflib
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.debug as debug

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
        config.add_option(
            'FAKED_THRESHOLD', short_option='t', default=0.6,
            help='Threshold used for the faked check',
            action='store', type='float')
        self._check_config = {}

    def render_text(self, outfd, data):

        def print_volatility_table(header, rows):
            # compute lengths
            lengths = map(lambda x: len(str(x)),
                          header)
            for row in rows:
                lengths = map(lambda x, y: max(len(str(x)), y),
                              row, lengths)
            lengths = map(lambda x: x + 1, lengths)
            outheader = map(lambda x, y: (x, '<{}'.format(y)),
                            header, lengths)
            self.table_header(outfd, outheader)
            for row in rows:
                self.table_row(outfd, *row)

        def print_pstree(psdict):

            def add_processes(ps_sorted, ps_level, ppid, level):
                pids = [ps['pid']
                        for ps in psdict.values()
                        if ps['ppid'] == ppid]
                for pid in pids:
                    ps_sorted.append(pid)
                    ps_level.append(level)
                    add_processes(ps_sorted, ps_level, pid, level + 1)

            def sort_processes(psdict):
                ps_sorted = []
                ps_level = []
                while len(ps_sorted) != len(psdict):
                    roots = [ps['pid']
                             for ps in psdict.values()
                             if (ps['ppid'] not in psdict.keys() and
                                 ps['pid'] not in ps_sorted)]
                    if not roots:
                        debug.warning("No root found")
                        break
                    root = roots[0]
                    ps_sorted.append(root)
                    ps_level.append(0)
                    add_processes(ps_sorted, ps_level, root, 1)
                return zip(ps_sorted, ps_level)

            def check_output(psdict, pid, check_name):
                check = psdict[pid]['check']
                return (''
                        if not check_name in check
                        else ('T'
                              if check[check_name]
                              else 'F'))

            outfd.write("PSTree\n")
            ps_sorted = sort_processes(psdict)
            table_header = ['Level', 'pid', 'ppid', 'Name',
                            'U', 'NC', 'NP', 'R', 'P', 'S', 'F']
            table_rows = []
            for (pid, level) in ps_sorted:
                row = ['.' * level,
                       pid,
                       psdict[pid]['ppid'],
                       psdict[pid]['name'],
                       check_output(psdict, pid, 'unique_names'),
                       check_output(psdict, pid, 'no_children'),
                       check_output(psdict, pid, 'no_parent'),
                       check_output(psdict, pid, 'reference_parents'),
                       check_output(psdict, pid, 'path'),
                       check_output(psdict, pid, 'static_pid'),
                       check_output(psdict, pid, 'faked')]
                table_rows.append(row)
            print_volatility_table(table_header, table_rows)

        def print_unique_names(entries, psdict):
            table_header = ['Name', 'Count', 'Pass']
            table_rows = []
            for entry in entries:
                count = len([x
                             for x in psdict.values()
                             if x['name'] == entry['name']])
                table_rows.append([entry['name'],
                                   count,
                                   'True'
                                   if entry['check']['unique_names']
                                   else 'False'])
            print_volatility_table(table_header, table_rows)

        def print_reference_parents(entries, psdict):
            table_header = ['Name', 'pid', 'Parent', 'ppid', 'Pass',
                            'Expected Parent']
            table_rows = []
            ref_parents = self._check_config['reference_parents']
            for entry in entries:
                table_rows.append([entry['name'],
                                   entry['pid'],
                                   psdict[entry['ppid']]['name'],
                                   entry['ppid'],
                                   'True'
                                   if entry['check']['reference_parents']
                                   else 'False',
                                   ref_parents[entry['name']]])
            print_volatility_table(table_header, table_rows)

        def print_path(entries, psdict):
            table_header = ['pid', 'Name', 'Path', 'Pass', 'Expected Path']
            table_rows = []
            for entry in entries:
                expected = self._check_config['path'][entry['name']]
                table_rows.append([entry['pid'],
                                   entry['name'],
                                   entry['path'],
                                   'True' if entry['check']['path'] else 'False',
                                   expected])
            print_volatility_table(table_header, table_rows)

        def print_no_children(entries, psdict):
            table_header = ['pid', 'Name', 'Pass', 'pid_child', 'Name_child']
            table_rows = []
            for entry in entries:
                if not entry['check']['no_children']:
                    children = [x['pid']
                                for x in psdict.values()
                                if x['ppid'] == entry['pid']]
                    for pid in children:
                        table_rows.append(entry['pid'],
                                          entry['name'],
                                          'False',
                                          pid,
                                          psdict[pid]['name'])
                else:
                    table_rows.append([entry['pid'],
                                       entry['name'],
                                       'True',
                                       '',
                                       ''])
            print_volatility_table(table_header, table_rows)

        def print_no_parent(entries, psdict):
            table_header = ['pid', 'ppid', 'Name', 'Pass', 'Parent name']
            table_rows = []
            for entry in entries:
                parent = (''
                          if entry['check']['no_parent']
                          else psdict[entry['ppid']]['name'])
                table_rows.append([entry['pid'],
                                   entry['ppid'],
                                   entry['name'],
                                   'True'
                                   if entry['check']['no_parent']
                                   else 'False',
                                   parent])
            print_volatility_table(table_header, table_rows)

        def print_static_pid(entries, psdict):
            table_header = ['pid', 'Name', 'Pass', 'Expected pid']
            table_rows = []
            for entry in entries:
                expected = self._check_config['static_pid'][entry['name']]
                table_rows.append([entry['pid'],
                                   entry['name'],
                                   'True'
                                   if entry['check']['static_pid']
                                   else 'False',
                                   expected])
            print_volatility_table(table_header, table_rows)

        def print_faked(entries, psdict):
            table_header = ['pid', 'Name', 'Pass', 'Faked name']
            table_rows = []
            threshold = self._config.faked_threshold
            check_entries = self._check_config['faked']
            for entry in entries:
                faked = ''
                if not entry['check']['faked']:
                    faked = difflib.get_close_matches(entry['name'],
                                                      check_entries,
                                                      1,
                                                      threshold)
                table_rows.append([entry['pid'],
                                   entry['name'],
                                   'True'
                                   if entry['check']['faked']
                                   else 'False',
                                   faked[0]])
            print_volatility_table(table_header, table_rows)

        def print_check(print_func, check_name, psdict):
            outfd.write("{} Check\n".format(check_name))
            entries = [ps for ps in psdict.values()
                       if 'check' in ps and check_name in ps['check']]
            if not entries:
                outfd.write(
                    "> No suspicious entries found (nothing inspected)\n")
            else:
                if self._config.VERBOSE:
                    print_func(entries, psdict)
                else:
                    suspicious_entries = [ps for ps in entries
                                          if not ps['check'][check_name]]
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
                       'no_parent': print_no_parent,
                       'reference_parents': print_reference_parents,
                       'path': print_path,
                       'static_pid': print_static_pid,
                       'faked': print_faked}
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
        for proc in psdict.values():
            if proc['name'] in check_entries:
                children = [x['pid'] for x in psdict.values()
                            if x['ppid'] == proc['pid']]
                proc['check']['no_children'] = not children

    def check_no_parent(self, psdict):
        check_entries = self._check_config['no_parent']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                parent = [x['pid'] for x in psdict.values()
                          if x['pid'] == proc['ppid']]
                proc['check']['no_parent'] = not parent

    def check_reference_parents(self, psdict):
        check_entries = self._check_config['reference_parents']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                expected = check_entries[proc['name']]
                parent = psdict[proc['ppid']]['name']
                check_pass = parent == expected
                proc['check']['reference_parents'] = check_pass

    def check_path(self, psdict):
        check_entries = self._check_config['path']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                path = proc['path'].lower() if proc['path'] else ""
                expected_path = check_entries[proc['name']].lower()
                proc['check']['path'] = path == expected_path

    def check_static_pid(self, psdict):
        check_entries = self._check_config['static_pid']
        for proc in psdict.values():
            if proc['name'] in check_entries.keys():
                check_pass = proc['pid'] == int(check_entries[proc['name']])
                proc['check']['static_pid'] = check_pass

    def check_faked(self, psdict):
        check_entries = self._check_config['faked']
        for proc in psdict.values():
            match = difflib.get_close_matches(proc['name'],
                                              check_entries,
                                              1,
                                              self._config.faked_threshold)
            if match:
                if match[0] != proc['name']:
                    proc['check']['faked'] = False
                else:
                    proc['check']['faked'] = True

    # Perform plugin checks. Currently it includes:
    # - unique_names
    # - no_children
    # - no_parent
    # - reference_parents
    # - path
    # - static_pid
    # - faked
    def checking(self, psdict):
        # For every check in the configuration perform the correspondent check.
        check_funcs = {'unique_names': self.check_unique_names,
                       'no_children': self.check_no_children,
                       'no_parent': self.check_no_parent,
                       'reference_parents': self.check_reference_parents,
                       'path': self.check_path,
                       'static_pid': self.check_static_pid,
                       'faked': self.check_faked}
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
        for rawproc in pslist:
            audit = rawproc.SeAuditProcessCreationInfo.ImageFileName.Name or ''
            proc = {'pid': int(rawproc.UniqueProcessId),
                    'ppid': int(rawproc.InheritedFromUniqueProcessId),
                    'name': str(rawproc.ImageFileName),
                    'ctime': str(rawproc.CreateTime),
                    'audit': str(audit),
                    'cmd': None,
                    'path': None,
                    'check': {}}
            process_params = rawproc.Peb.ProcessParameters
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
