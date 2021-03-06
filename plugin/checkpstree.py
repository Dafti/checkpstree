# Volatility
#
# Authors
# Tony Gerard <tony.gerard@cfa-afti.fr>
# Francois-Xavier Babin <francois-xavier.babin@cfa-afti.fr>
# Eric Jouenne <eric.jouenne@cfa-afti.fr>
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

"""Volatility plugin: Checkpstree"""
import os.path
import json
import difflib
import ntpath
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.debug as debug
import volatility.plugins.getsids as getsids_mod

#pylint: disable-msg=C0111

def _find_root(pidlist, psdict):
    """From the input list of pids find a pid that is a root, i.e.
    it has no parent in the process tree"""
    # follow the pid/ppid one of the processes until we find
    # a process without parent
    seen = list()
    pid = pidlist[0]
    while pid in pidlist and pid not in seen:
        seen.append(pid)
        pid = int(psdict[pid]['ppid'])
    # the root process is the last in the seen list
    return seen[-1]

def _find_roots_and_leafs(psdict):
    """From a dictionary of processes find which ones are root and which ones
    leafs."""
    pslist = psdict.keys()
    leafs = []
    roots = []
    rmlist = []
    # helper function to recursively remove children of the given pid
    # from the pslist
    def _process_children(pid):
        children = [x['pid']
                    for x in psdict.values()
                    if x['ppid'] == pid and x['pid'] not in rmlist]
        if not children:
            leafs.append(pid)
        for child in children:
            pslist.remove(child)
            rmlist.append(child)
        for child in children:
            _process_children(child)

    # while the list is not empty
    while pslist:
        root = _find_root(pslist, psdict)
        roots.append(root)
        rmlist.append(root)
        pslist.remove(root)
        _process_children(root)
    return (roots, leafs)


class CheckPSTree(common.AbstractWindowsCommand):
    """Print process list as a tree and perform check on common anomalies."""
    # Declare meta information associated with this plugin
    meta_info = {
        'author': ['Tony Gerard', 'Francois-Xavier Babin',
            'Eric Jouenne', 'Daniel Gracia Perez'],
        'copyright': 'Copyright (c) 2018 ' +
                     'Tony Gerard, ' +
                     'Francois-Xavier Babin, ' +
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
        config.add_option(
            'SUSPICIOUS_THRESHOLD', short_option='s', default=0.9,
            help='Threshold used for the suspicious check',
            action='store', type='float')
        self._check_config = {}

    def render_text(self, outfd, data):
        """Output checks results in textual format."""
        # All the functions to print checks results build a table and send
        # it to the `print_volatility_table` helper function to effectively
        # print it out.
        # The only print function not using that helper function, new checks
        # should exploit it.

        def print_volatility_table(header, rows):
            """`render_text` utility function to print nice tables."""
            # compute column lengths as the length of the longest entry
            # including the header plus 1
            lengths = map(lambda x: len(str(x)) + 1,
                          header)
            for row in rows:
                lengths = map(lambda x, y: max(len(str(x)) + 1, y),
                              row, lengths)
            # prepare the header for the renderer: list of tuples with
            # the column name and the width combined with the alignment
            outheader = map(lambda x, y: (x, '<{}'.format(y)),
                            header, lengths)
            # print out the table
            self.table_header(outfd, outheader)
            for row in rows:
                self.table_row(outfd, *row)

        def print_pstree(psdict):
            """Prints the provided list of processes in a tree format
            with an overview of the checks result."""

            def add_processes(ps_sorted, ps_level, ppid, level):
                """Add the provided pid children and descendants in the list of
                sorted processes"""
                pids = [ps['pid']
                        for ps in psdict.values()
                        if ps['ppid'] == ppid and ps['pid'] not in ps_sorted]
                for pid in pids:
                    ps_sorted.append(pid)
                    ps_level.append(level)
                    add_processes(ps_sorted, ps_level, pid, level + 1)

            def sort_processes(psdict):
                """Utility method to create a printable tree of the
                provided processes dictionary."""
                ps_sorted = []
                ps_level = []
                roots = [x['pid'] for x in psdict.values() if x['root']]
                for root in roots:
                    ps_sorted.append(root)
                    ps_level.append(0)
                    add_processes(ps_sorted, ps_level, root, 1)
                return zip(ps_sorted, ps_level)

            def check_output(psdict, pid, check_name):
                """Return the result of a check in string format: '' if the
                check was not done for the given pid, 'T' if it was successful,
                and 'F' if not."""
                check = psdict[pid]['check']
                return (''
                        if not check_name in check
                        else ('T'
                              if check[check_name]
                              else 'F'))

            outfd.write("PSTree\n")
            ps_sorted = sort_processes(psdict)
            table_header = ['Level', 'pid', 'ppid', 'Name',
                            'U', 'NC', 'NP', 'R', 'P', 'SP', 'F', 'S', 'SI']
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
                       check_output(psdict, pid, 'faked'),
                       check_output(psdict, pid, 'suspicious'),
                       check_output(psdict, pid, 'sids')]
                table_rows.append(row)
            print_volatility_table(table_header, table_rows)
            outfd.write("\n")

        def print_unique_names(entries, psdict):
            """Print results of the unique_name check."""
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
            """Print results of the reference_parents check."""
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
            """Print result of the path check."""
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
            """Print result of no_children check."""
            table_header = ['pid', 'Name', 'Pass', 'pid_child', 'Name_child']
            table_rows = []
            for entry in entries:
                if not entry['check']['no_children']:
                    children = [x['pid']
                                for x in psdict.values()
                                if x['ppid'] == entry['pid']]
                    for pid in children:
                        table_rows.append([entry['pid'],
                                           entry['name'],
                                           'False',
                                           pid,
                                           psdict[pid]['name']])
                else:
                    table_rows.append([entry['pid'],
                                       entry['name'],
                                       'True',
                                       '',
                                       ''])
            print_volatility_table(table_header, table_rows)

        def print_no_parent(entries, psdict):
            """Print result of no_parent check."""
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
            """Print result of static_pid check."""
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
            """Print result of faked check."""
            table_header = ['pid', 'Name', 'Pass', 'Faked name']
            table_rows = []
            threshold = self._config.faked_threshold
            check_entries = map(lambda x: x.lower(),
                                self._check_config['faked'])
            for entry in entries:
                faked = ['']
                if not entry['check']['faked']:
                    faked = difflib.get_close_matches(entry['name'].lower(),
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

        def print_suspicious(entries, psdict):
            """Print result of suspicious check."""
            table_header = ['pid', 'Name', 'Pass', 'Suspicious name']
            table_rows = []
            threshold = self._config.suspicious_threshold
            check_entries = map(lambda x: x.lower(),
                                self._check_config['suspicious'])
            for entry in entries:
                suspicious = ['']
                if 'suspicious' in entry['check']:
                    suspicious = difflib.get_close_matches(entry['name'].lower(),
                                                           check_entries,
                                                           1,
                                                           threshold)
                table_rows.append([entry['pid'],
                                   entry['name'],
                                   'True'
                                   if entry['check']['suspicious']
                                   else 'False',
                                   suspicious[0]])
            print_volatility_table(table_header, table_rows)

        def print_sids(entries, psdict):
            """Print result of sids check."""
            table_header = ['pid', 'Name', 'Pass', 'Found SID']
            table_rows = []
            check_entries = self._check_config['sids']
            # my_dict = {}
            for entry in entries:
                # if entry['name'] not in my_dict:
                #     my_dict[entry['name']] = []
                # my_dict[entry['name']].extend(entry['sids'])
                found = set(entry['sids'])
                expected = set(check_entries[entry['name'].lower()])
                in_both = list(found.intersection(expected))
                in_entry = list(found - expected)
                in_expected = list(expected - found)
                if self._config.VERBOSE:
                    for sid in in_both:
                        table_rows.append([entry['pid'],
                                           entry['name'],
                                           'True',
                                           sid])
                for sid in in_entry:
                    table_rows.append([entry['pid'],
                                       entry['name'],
                                       'False',
                                       sid])
                # diff = map(lambda x, y: (x if x else '', y if y else ''),
                #         in_entry, in_expected)
                # for (proc_sid, expected_sid) in diff:
                #     table_rows.append([entry['pid'],
                #                        entry['name'],
                #                        'False',
                #                        proc_sid,
                #                        expected_sid])
            print_volatility_table(table_header, table_rows)
            # for (k,v) in my_dict.iteritems():
            #     outfd.write("{} = {}\n".format(k, list(set(v))))

        def print_check(print_func, check_name, psdict):
            """Wrapper function for the print check functions: do the common
            work of checking if there was that was inspected and faulty in
            the requested check."""
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

        def print_checks(psdict):
            print_funcs = {'unique_names': print_unique_names,
                           'no_children': print_no_children,
                           'no_parent': print_no_parent,
                           'reference_parents': print_reference_parents,
                           'path': print_path,
                           'static_pid': print_static_pid,
                           'faked': print_faked,
                           'suspicious': print_suspicious,
                           'sids': print_sids}
            for key in self._check_config.keys():
                if key in print_funcs.keys():
                    print_check(print_funcs[key], key, psdict)

        psdict = data['psdict']
        outfd.write("""
===============================================================================
CheckPSTree analysis report

""")
        print_pstree(psdict)
        print_checks(psdict)
        outfd.write("""
===============================================================================

""")

    def check_unique_names(self, psdict):
        """Check if names defined in the config appear at most once in the
        process list."""
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
        """Check if names defined in the config don't have any childreen"""
        # Because processes already have annotations indicating if they are
        # a leaf, checking if a process has or hasn't children is just
        # checking if the process is a leaf or not.
        check_entries = self._check_config['no_children']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                # Simply check that the process is leaf or not
                proc['check']['no_children'] = proc['leaf']

    def check_no_parent(self, psdict):
        """Check if names defined in the config are a root of the process
        tree."""
        # Because processes already have annotations indicating if they are
        # a root, checking if a process is root is just checking the
        # annotation.
        check_entries = self._check_config['no_parent']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                # Simply check that the process is root or not
                proc['check']['no_parent'] = proc['root']

    def check_reference_parents(self, psdict):
        """Check if the names defined in the config have as parent process
        the one indicated in the config."""
        check_entries = self._check_config['reference_parents']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                # If the process is a root of the process tree then it can't
                # pass the check, because it will never have the parent
                # indicated in the config.
                check_pass = not proc['root']
                if check_pass:
                    expected = check_entries[proc['name']]
                    parent = psdict[proc['ppid']]['name']
                    check_pass = parent == expected
                proc['check']['reference_parents'] = check_pass

    def check_path(self, psdict):
        """Check if the names defined in the config have the defined path."""
        check_entries = self._check_config['path']
        for proc in psdict.values():
            if proc['name'] in check_entries:
                # As Windows is caseless we compare the found path and the
                # defined path as lowercase, to make sure that the difference
                # that might be found is a letter that in one case is capital
                # and in the other no.
                path = proc['path'].lower() if proc['path'] else ""
                expected_path = check_entries[proc['name']].lower()
                proc['check']['path'] = path == expected_path

    def check_static_pid(self, psdict):
        """Check if the names defined in the config have the defined pid."""
        check_entries = self._check_config['static_pid']
        for proc in psdict.values():
            if proc['name'] in check_entries.keys():
                check_pass = proc['pid'] == int(check_entries[proc['name']])
                proc['check']['static_pid'] = check_pass

    def check_faked(self, psdict):
        """Check if the names defined in the config have processes with names
        that are very similar.
        If so it means that the found processes are maybe trying to cheat the
        user making him/her believe it's a valid process.

        This check can be configured in the command line.
        This check may raise a large number of false positives."""
        check_entries = map(lambda x: x.lower(), self._check_config['faked'])
        threshold = self._config.faked_threshold
        for proc in psdict.values():
            # The difflib lib is used to check the names' similarity.
            match = difflib.get_close_matches(proc['name'].lower(),
                                              check_entries,
                                              1,
                                              threshold)
            if match:
                if match[0] != proc['name'].lower():
                    proc['check']['faked'] = False
                else:
                    proc['check']['faked'] = True

    def check_suspicious(self, psdict):
        """Check if the suspicious names defined in the config are among the
        processes in the image or if there are similar ones."""
        check_entries = map(lambda x: x.lower(),
                            self._check_config['suspicious'])
        threshold = self._config.suspicious_threshold
        for proc in psdict.values():
            match = difflib.get_close_matches(proc['name'].lower(),
                                              check_entries,
                                              1,
                                              threshold)
            if match:
                if match[0] != proc['name'].lower():
                    proc['check']['suspicious'] = True
                else:
                    proc['check']['suspicious'] = False

    def check_sids(self, psdict):
        """Check if the processes have the expected sids."""
        check_entries = self._check_config['sids']
        for proc in psdict.values():
            if proc['name'].lower() in check_entries:
                found = set(proc['sids'])
                expected = set(check_entries[proc['name'].lower()])
                # diff = list(found.symmetric_difference(expected))
                diff = list(found - expected)
                proc['check']['sids'] = True if not diff else False

    def checking(self, psdict):
        """Perform plugin checks. Currently it includes:
        - unique_names
        - no_children
        - no_parent
        - reference_parents
        - path
        - static_pid
        - faked
        - suspicious
        - sids"""
        # For every check in the configuration perform the correspondent check.
        check_funcs = {'unique_names': self.check_unique_names,
                       'no_children': self.check_no_children,
                       'no_parent': self.check_no_parent,
                       'reference_parents': self.check_reference_parents,
                       'path': self.check_path,
                       'static_pid': self.check_static_pid,
                       'faked': self.check_faked,
                       'suspicious': self.check_suspicious,
                       'sids': self.check_sids}
        for key in self._check_config.keys():
            if key in check_funcs.keys():
                check_funcs[key](psdict)

    def check_config(self):
        """Check the configuration file.

        If no configuration was provided we try to load a configuration file
        from `<plugin_path>/checkpstree_configs/<profile>.json` profile being
        the value in `self._config.PROFILE`.
        If the user specifies another configuration file in
        `self._config.CONFIG` then the user specified file is loaded."""
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

    def __get_processes_sids(self):
        getsids = getsids_mod.GetSIDs(self._config)
        output_getsids = getsids.unified_output(getsids.calculate())
        def sidvisit(node, accum):
            pid = int(node.values[0])
            if pid not in accum:
                accum[pid] = []
            sid = node.values[3]
            accum[pid].append(sid)
            return accum
        siddict = output_getsids.visit(None, sidvisit, {})
        return siddict

    def build_psdict(self):
        """Transform the raw processes from the provided memory dump into a
        dictionary of processed processes indexed by their pid."""
        addr_space = utils.load_as(self._config)
        pslist = tasks.pslist(addr_space)
        pidsids_dict = self.__get_processes_sids()
        psdict = {}
        for rawproc in pslist:
            audit = rawproc.SeAuditProcessCreationInfo.ImageFileName.Name or ''
            pid = int(rawproc.UniqueProcessId)
            proc = {'pid': pid,
                    'ppid': int(rawproc.InheritedFromUniqueProcessId),
                    'name': str(rawproc.ImageFileName),
                    'ctime': str(rawproc.CreateTime),
                    'audit': str(audit),
                    'cmd': None,
                    'path': None,
                    'sids': pidsids_dict[int(rawproc.UniqueProcessId)]
                            if pid in pidsids_dict
                            else None,
                    # for the moment no one is root, it will be decided later
                    'root': False,
                    # for the moment no one is leaf, it will be decided later
                    'leaf': False,
                    'check': {}}
            process_params = rawproc.Peb.ProcessParameters
            if process_params:
                proc['cmd'] = str(process_params.CommandLine)
                proc['path'] = str(process_params.ImagePathName)
                # if we have the path we can extract the fullname of the
                # application which is sometimes truncated in the
                # process.ImageFileName
                proc['name'] = ntpath.basename(proc['path'])
            # check if the pid has already been seen, if so inform the user
            # and don't include the current process in the list of processes
            # that will be analyzed
            if proc['pid'] in psdict:
                debug.warning(("pid {} found two times in the process list. " +
                               "Skipping the following entry {}.").format(
                                   proc['pid'], proc))
                continue
            psdict[proc['pid']] = proc
        # We need to determine which are the roots and also the leafs
        # this information is needed to have some coherence between our checks
        # and the process tree that is printed.
        (roots, leafs) = _find_roots_and_leafs(psdict)
        for root in roots:
            psdict[root]['root'] = True
        for leaf in leafs:
            psdict[leaf]['leaf'] = True
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
