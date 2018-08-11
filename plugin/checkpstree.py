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
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.pstree as pstree
from volatility.renderers.basic import Address,Hex
import volatility.plugins.vadinfo as vadinfo
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
        # Render the PSTree output
        pstree.PSTree.render_text(self, outfd, data["pstree"])
        check_data = data["check"]
        outfd.write("""
===============================================================================
Analysis report
""")
        def printProcs(indent, pstree):
            for p in pstree:
                outfd.write("{}{} {} \-/ {} \-/ {}\n".format('.' * indent, p['pid'], p['name'],
                    p['peb']['fullname'] if p['peb']['fullname'] is not None else '<None>',
                    p['vad']['filename'] if p['vad']['filename'] is not None else '<None>'))
                printProcs(indent + 1, p['children'])

        def printUniqueNames(entries):
            outfd.write("Unique Names Check\n")
            self.table_header(outfd,
                    [("Name", "<50"),
                     ("Count", ">6"),
                     ("Pass", ">6")])
            for e in entries:
                self.table_row(outfd,
                        e['name'],
                        e['count'],
                        'True' if e['pass'] else 'False')
            outfd.write("\n")


        def printReferenceParents(entries):
            outfd.write("Reference Parents Check\n")
            self.table_header(outfd,
                    [('Name', '<50'),
                        ('pid', '>6'),
                        ('Parent', '<50'),
                        ('ppid', '>6'),
                        ('Pass', '>6'),
                        ('Expected Parent', '<50')])
            for e in entries:
                self.table_row(outfd,
                    e['name'],
                    e['pid'],
                    e['parent'],
                    e['ppid'],
                    'True' if e['pass'] else 'False',
                    self._check_config['reference_parents'][e['name']]
                    )
            outfd.write("\n")

        def printPebFullname(entries):
            outfd.write("Path(PEB) Check\n")
            self.table_header(outfd,
                    [('pid', '>6'),
                     ('Name', '<20'),
                     ('Path', '<40'),
                     ('Pass', '>6'),
                     ('Expected Path', '<40')])
            for e in entries:
                self.table_row(outfd,
                    e['pid'],
                    e['name'],
                    e['fullname'],
                    'True' if e['pass'] else 'False',
                    self._check_config['peb_fullname'][e['name']]
                    )
            outfd.write("\n")

        def printVadFilename(entries):
            outfd.write("Path(VAD) Check\n")
            self.table_header(outfd,
                    [('pid', '>6'),
                     ('Name', '<20'),
                     ('Path', '<40'),
                     ('Pass', '>6'),
                     ('Expected Path', '<40')])
            for e in entries:
                self.table_row(outfd,
                    e['pid'],
                    e['name'],
                    e['filename'],
                    'True' if e['pass'] else 'False',
                    self._check_config['vad_filename'][e['name']]
                    )
            outfd.write("\n")

        outfd.write("PSTree\n")
        printProcs(0, check_data['pstree'])
        outfd.write("\n")
        check = check_data['check']
        if 'unique_names' in check:
            printUniqueNames(check['unique_names'])
        if 'reference_parents' in check:
            printReferenceParents(check['reference_parents'])
        if 'peb_fullname' in check:
            printPebFullname(check['peb_fullname'])
        if 'vad_filename' in check:
            printVadFilename(check['vad_filename'])


    def buildPsTree(self, pslist):

        # Try to find a tree node which is parent to the passed process (child) and attach it to it
        def attachChild(child, pstree):
            # At each root node of the current tree check if the current process node is a child of
            # it. If not a child of the root node, try to see if it is a child of one of the root
            # node children by recursively calling the attachChild function.
            # If we were able to find a the parent of the process then return True, otherwise False.
            # TODO: we could stop the loop if a parent was found.
            for parent in pstree:
                if parent['pid'] == child['ppid']:
                    parent['children'].append(child)
                    return True
                else:
                    if attachChild(child, parent['children']):
                        return True
            return False

        # Create a tree node
        def createPsNode(task):
            proc = {'pid': int(task.UniqueProcessId),
                    'ppid': int(task.InheritedFromUniqueProcessId),
                    'name': str(task.ImageFileName),
                    'ctime': str(task.CreateTime),
                    'proc': task,
                    'children': []}
            peb_cmdline = None
            peb_image_baseaddr = Address(0)
            peb_baseaddr = Address(0)
            peb_size = Hex(0)
            peb_basename = None
            peb_fullname = None
            vad_filename = '<No VAD>'
            vad_baseaddr = Address(0)
            vad_size = Hex(0)
            vad_protection = '<No VAD>'
            vad_tag = '<No VAD>'
            if task.Peb:
                peb_cmdline = task.Peb.ProcessParameters.CommandLine
                mods = task.get_load_modules()
                for mod in mods:
                    ext = os.path.splitext(str(mod.FullDllName))[1].lower()
                    if ext == '.exe':
                        peb_image_baseaddr = Address(task.Peb.ImageBaseAddress)
                        peb_baseaddr = Address(mod.DllBase)
                        peb_size = Hex(0)
                        peb_basename = str(mod.BaseDllName)
                        peb_fullname = str(mod.FullDllName)
                        break
                for vad, addr_space in task.get_vads(vad_filter = task._mapped_file_filter):
                    ext = ""
                    vad_found = False
                    if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = addr_space).e_magic != 0x5A4D:
                        continue
                    if str(vad.FileObject.FileName or ''):
                        ext = os.path.splitext(str(vad.FileObject.FileName))[1].lower()
                    if (ext == ".exe") or (vad.Start == task.Peb.ImageBaseAddress):
                        vad_filename =  str(vad.FileObject.FileName)
                        vad_baseaddr = Address(vad.Start)
                        vad_size = Hex(vad.End - vad.Start)
                        vad_protection = str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v()) or '')
                        vad_tag = str(vad.Tag or '')
                        vad_found = True
                        break
                if vad_found == False:
                    vad_filename = 'NA'
                    vad_baseaddr = Address(0)
                    vad_size = Hex(0)
                    vad_protection = 'NA'
                    vad_tag = 'NA'
            proc['peb'] = {
                    'cmdline': peb_cmdline,
                    'image_baseaddr': peb_image_baseaddr,
                    'baseaddr': peb_baseaddr,
                    'size': peb_size,
                    'basename': peb_basename,
                    'fullname': peb_fullname}
            proc['vad'] = {'filename': vad_filename,
                    'baseaddr': vad_baseaddr,
                    'size': vad_size,
                    'protection': vad_protection,
                    'tag': vad_tag}
            return proc

        def addPs(task, pstree):
            # create a tree node from the raw process
            proc = createPsNode(task)
            # check if one of the root nodes in the current process tree is a child of the
            # node we have created, if so remove it from the tree root and put it as a child
            # of the created node
            for index, child in enumerate(pstree):
                if child['ppid'] == proc['pid']:
                    proc['children'].append(child)
                    del pstree[index]
            # try to attach the current node in one of the nodes of the current tree,
            # otherwise put it in the root of the tree
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
                if ps['name'] == name:
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


    def checkReferenceParents(self, pstree):
        report = []
        ref_parents = self._check_config['reference_parents']
        def checkReferenceParent(parent, pstree):
            for ps in pstree:
                if ps['name'] in ref_parents.keys():
                    report.append({
                        'pid': ps['pid'],
                        'ppid': ps['ppid'],
                        'name': ps['name'],
                        'parent': parent,
                        'pass': parent == ref_parents[ps['name']]})
                checkReferenceParent(str(ps['proc'].ImageFileName),
                    ps['children'])
        for ps in pstree:
            checkReferenceParent(ps['name'], ps['children'])
        return report


    def findNodes(self, pstree, match_func):
        nodes = []
        for ps in pstree:
            if match_func(ps):
                nodes.append(ps)
            nodes.extend(self.findNodes(ps['children'], match_func))
        return nodes


    def checkPebFullname(self, pstree):
        report = []
        peb_entries = self._check_config['peb_fullname']
        for name, path in peb_entries.iteritems():
            nodes = self.findNodes(pstree, lambda node: node['name'] == name)
            for node in nodes:
                report.append({
                    'pid': node['pid'],
                    'ppid': node['ppid'],
                    'name': node['name'],
                    'fullname': node['peb']['fullname'],
                    'pass': node['peb']['fullname'].lower() == path.lower()})
        return report


    def checkVadFilename(self, pstree):
        report = []
        vad_entries = self._check_config['vad_filename']
        for name, path in vad_entries.iteritems():
            nodes = self.findNodes(pstree, lambda node: node['name'] == name)
            for node in nodes:
                report.append({
                    'pid': node['pid'],
                    'ppid': node['ppid'],
                    'name': node['name'],
                    'filename': node['vad']['filename'],
                    'pass': node['vad']['filename'] == path})
        return report


    # Perform plugin checks. Currently it includes:
    # - unique_names
    # - reference_parents
    def checking(self, pslist):
        # A tree structure (with multiple roots) is created from the processes
        # list. This structure will be used to perform the plugin checks.
        pstree = self.buildPsTree(pslist)
        check = {}
        # For every check in the configuration perform the correspondent check.
        # For each configured check create a report.
        if 'unique_names' in self._check_config:
            report = self.checkUniqueNames(pstree)
            check['unique_names'] = report
        if 'reference_parents' in self._check_config:
            check['reference_parents'] = self.checkReferenceParents(pstree)
        if 'peb_fullname' in self._check_config:
            check['peb_fullname'] = self.checkPebFullname(pstree)
        if 'vad_filename' in self._check_config:
            check['vad_filename'] = self.checkVadFilename(pstree)
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
        # Check the plugin configuration
        self.checkConfig()
        # We get the output of PSTree.calculate, this output will be later displayed in the
        # the render_text method.
        # Currently the PSTree.calculate output is not used for anything else, and as such it
        # could be removed.
        # Note that the PSTree plugin doesn't structure the processes as a tree, it only
        # displays them as a tree.
        psdict = pstree.PSTree.calculate(self)
        # Get the list of process
        addr_space = utils.load_as(self._config)
        pslist = tasks.pslist(addr_space)
        # Perform plugin checks
        check_data = self.checking(pslist)
        # Return output data (data that can be printed in the console)
        # Again, the output of PSTree.calculate (psdict) could be removed as the same data
        # is available in the plugin checked data
        return { "pstree": psdict, "check": check_data }
