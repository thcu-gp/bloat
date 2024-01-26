#!/usr/bin/python
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import operator
import argparse
import os
import re
import subprocess
import sys
import json

from typing import Any, Dict, Iterable, List, Optional, Tuple


def format_bytes(bytes: int) -> str:
    """Pretty-print a number of bytes."""
    if bytes > 1e6:
        bytes = bytes / 1.0e6
        return '%.1fm' % bytes
    if bytes > 1e3:
        bytes = bytes / 1.0e3
        return '%.1fk' % bytes
    return str(bytes)


def symbol_type_to_human(type_: str) -> str:
    """Convert a symbol type as printed by nm into a human-readable name."""
    return {
        'b': 'bss',
        'd': 'data',
        'r': 'read-only data',
        't': 'code',
        'u': 'weak symbol',  # Unique global.
        'w': 'weak symbol',
        'v': 'weak symbol'
        }[type_]


def parse_nm(nm_input: Iterable) -> Tuple[str, str, int, Optional[str]]:
    """Parse nm output.

    Argument: an iterable over lines of nm output.

    Yields: (symbol name, symbol type, symbol size, source file path).
    Path may be None if nm couldn't figure out the source file.
    """

    # Match lines with size + symbol + optional filename.
    sym_re = re.compile(r'^[\da-f]+ ([\da-f]+) (.) ([^\t]+)(?:\t(.*):\d+)?$')

    # Match lines with addr but no size.
    addr_re = re.compile(r'^[\da-f]+ (.) ([^\t]+)(?:\t.*)?$')

    # Match lines without an address -- typically external symbols.
    noaddr_re = re.compile(r'^ + (.) (.*)$')

    for line in nm_input:
        line = line.rstrip()
        match = sym_re.match(line)
        if match:
            size, type_, sym = match.groups()[0:3]
            size = int(size, 16)
            type_ = type_.lower()
            if type_ in ['u', 'v']:
                type_ = 'w'  # just call them all weak
            elif type_ == 'b':
                continue  # skip all BSS for now
            path = match.group(4)
            yield sym, type_, size, path
            continue
        match = addr_re.match(line)
        if match:
            type_, sym = match.groups()[0:2]
            # No size == we don't care.
            continue
        match = noaddr_re.match(line)
        if match:
            type_, sym = match.groups()
            if type_ in ('U', 'w'):
                # external or weak symbol
                continue

        print('unparsed: ' + repr(line), file=sys.stderr)


def demangle(ident: str, cppfilt: Optional[str]) -> str:
    if cppfilt and ident.startswith('_Z'):
        # Demangle names when possible. Mangled names all start with _Z.
        ident = subprocess.check_output([cppfilt, ident]).strip()
    return ident


class Suffix:
    def __init__(self, suffix: str, replacement):
        self.pattern = r'^(.*)' + suffix + r'(.*)$'
        self.re = re.compile(self.pattern)
        self.replacement = replacement


class SuffixCleanup:
    """Pre-compile suffix regular expressions."""
    def __init__(self):
        self.suffixes = [
            Suffix(r'\.part\.(\d+)', 'part'),
            Suffix(r'\.constprop\.(\d+)', 'constprop'),
            Suffix(r'\.isra\.(\d+)', 'isra'),
        ]

    def cleanup(self, ident: str, cppfilt: Optional[str]) -> str:
        """Cleanup identifiers that have suffixes preventing demangling,
           and demangle if possible."""
        to_append: List[str] = []
        for s in self.suffixes:
            found = s.re.match(ident)
            if not found:
                continue
            to_append += [' [' + s.replacement + '.' + found.group(2) + ']']
            ident = found.group(1) + found.group(3)
        if len(to_append):
            # Only try to demangle if there were suffixes.
            ident = demangle(ident, cppfilt)

        new_ident = ident + ''.join(to_append)
        return new_ident


suffix_cleanup = SuffixCleanup()


def parse_cpp_name(name: str, cppfilt: Optional[str]) -> List[str]:
    name = suffix_cleanup.cleanup(name, cppfilt)

    # Turn prefixes into suffixes so namespacing works.
    prefixes = [
        ['bool ', ''],
        ['construction vtable for ', ' [construction vtable]'],
        ['global constructors keyed to ', ' [global constructors]'],
        ['guard variable for ', ' [guard variable]'],
        ['int ', ''],
        ['non-virtual thunk to ', ' [non-virtual thunk]'],
        ['typeinfo for ', ' [typeinfo]'],
        ['typeinfo name for ', ' [typeinfo name]'],
        ['virtual thunk to ',  ' [virtual thunk]'],
        ['void ', ''],
        ['vtable for ', ' [vtable]'],
        ['VTT for ', ' [VTT]'],
    ]
    for prefix, replacement in prefixes:
        if name.startswith(prefix):
            name = name[len(prefix):] + replacement
    # Simplify parenthesis parsing.
    replacements = [
        ['(anonymous namespace)', '[anonymous namespace]'],
    ]
    for value, replacement in replacements:
        name = name.replace(value, replacement)

    def parse_one(val: str) -> Tuple[str, str]:
        """Returns (leftmost-part, remaining)."""
        if (val.startswith('operator') and
                not (val[8].isalnum() or val[8] == '_')):
            # Operator overload function, terminate.
            return (val, '')
        co = val.find('::')
        lt = val.find('<')
        pa = val.find('(')
        co = len(val) if co == -1 else co
        lt = len(val) if lt == -1 else lt
        pa = len(val) if pa == -1 else pa
        if co < lt and co < pa:
            # Namespace or type name.
            return (val[:co], val[co+2:])
        if lt < pa:
            # Template. Make sure we capture nested templates too.
            open_tmpl = 1
            gt = lt
            while val[gt] != '>' or open_tmpl != 0:
                gt = gt + 1
                if val[gt] == '<':
                    open_tmpl = open_tmpl + 1
                if val[gt] == '>':
                    open_tmpl = open_tmpl - 1
            ret = val[gt+1:]
            if ret.startswith('::'):
                ret = ret[2:]
            if ret.startswith('('):
                # Template function, terminate.
                return (val, '')
            return (val[:gt+1], ret)
        # Terminate with any function name, identifier, or unmangled name.
        return (val, '')

    parts = []
    while len(name) > 0:
        (part, name) = parse_one(name)
        assert len(part) > 0
        parts.append(part)
    return parts


def treeify_syms(symbols: str, strip_prefix: Optional[str] = None,
                 cppfilt: Optional[str] = None):
    dirs = {}
    for sym, type_, size, path in symbols:
        if path:
            path = os.path.normpath(path)
            if strip_prefix and path.startswith(strip_prefix):
                path = path[len(strip_prefix):]
            elif path.startswith('/'):
                path = path[1:]
            path = ['[path]'] + path.split('/')

        parts = parse_cpp_name(sym, cppfilt)
        if len(parts) == 1:
            if path:
                # No namespaces, group with path.
                parts = path + parts
            else:
                new_prefix = ['[ungrouped]']
                regroups = [
                    ['.L.str', '[str]'],
                    ['.L__PRETTY_FUNCTION__.', '[__PRETTY_FUNCTION__]'],
                    ['.L__func__.', '[__func__]'],
                    ['.Lswitch.table', '[switch table]'],
                ]
                for prefix, group in regroups:
                    if parts[0].startswith(prefix):
                        parts[0] = parts[0][len(prefix):]
                        parts[0] = demangle(parts[0], cppfilt)
                        new_prefix += [group]
                        break
                parts = new_prefix + parts

        key = parts.pop()
        tree = dirs
        try:
            depth = 0
            for part in parts:
                depth = depth + 1
                assert part != '', path
                if part not in tree:
                    tree[part] = {'bloat_symbols': {}}
                if type_ not in tree[part]['bloat_symbols']:
                    tree[part]['bloat_symbols'][type_] = 0
                tree[part]['bloat_symbols'][type_] += 1
                tree = tree[part]
            old_size, old_symbols = tree.get(key, (0, {}))
            if type_ not in old_symbols:
                old_symbols[type_] = 0
            old_symbols[type_] += 1
            tree[key] = (old_size + size, old_symbols)
        except KeyError:
            print('sym `%s`\tparts `%s`\tkey `%s`' % (sym, parts, key),
                  file=sys.stderr)
            raise
    return dirs


def jsonify_tree(tree: Dict[str, Any], name: str):
    children = []
    total = 0

    for key, val in tree.items():
        if key == 'bloat_symbols':
            continue
        if isinstance(val, dict):
            subtree = jsonify_tree(val, key)
            total += subtree['data']['area']
            children.append(subtree)
        else:
            (size, symbols) = val
            total += size
            assert len(symbols) == 1, list(symbols.values())[0] == 1
            symbol = symbol_type_to_human(list(symbols.keys())[0])
            children.append({
                    'name': key + ' ' + format_bytes(size),
                    'data': {
                        'area': size,
                        'symbol': symbol,
                    }
            })

    children.sort(key=lambda child: -child['data']['area'])
    dominant_symbol = ''
    if 'bloat_symbols' in tree:
        dominant_symbol = symbol_type_to_human(
            max(tree['bloat_symbols'].items(),
                key=operator.itemgetter(1))[0])
    return {'name': name + ' ' + format_bytes(total),
            'data': {'area': total,
                     'dominant_symbol': dominant_symbol, },
            'children': children, }


def dump_nm(nmfile: Iterable, strip_prefix: str, cppfilt: Optional[str]):
    dirs = treeify_syms(parse_nm(nmfile), strip_prefix, cppfilt)
    string = ('var kTree = ' + json.dumps(jsonify_tree(dirs, '[everything]'),
                                          indent=2))
    return string


def parse_objdump(input):
    """Parse objdump -h output."""
    sec_re = re.compile(r'^\d+ (\S+) +([\da-z]+)')
    sections = []
    debug_sections = []

    for line in input:
        line = line.strip()
        match = sec_re.match(line)
        if match:
            name, size = match.groups()
            if name.startswith('.'):
                name = name[1:]
            if name.startswith('debug_'):
                name = name[len('debug_'):]
                debug_sections.append((name, int(size, 16)))
            else:
                sections.append((name, int(size, 16)))
            continue
    return sections, debug_sections


def jsonify_sections(name, sections):
    children = []
    total = 0
    for section, size in sections:
        children.append({
                'name': section + ' ' + format_bytes(size),
                'data': {'area': size}
                })
        total += size

    children.sort(key=lambda child: -child['data']['area'])

    return {
        'name': name + ' ' + format_bytes(total),
        'data': {'area': total},
        'children': children
        }


def export(output_file: Optional[str], string: str) -> None:
    if not output_file:
        print(string)
    else:
        with open(output_file, 'w') as of:
            of.write(string)


def dump_sections(objdump) -> str:
    sections, debug_sections = parse_objdump(objdump)
    sections = jsonify_sections('sections', sections)
    debug_sections = jsonify_sections('debug', debug_sections)
    size = sections['data']['area'] + debug_sections['data']['area']
    string = ('var kTree = ' + json.dumps({
              'name': 'top ' + format_bytes(size),
              'data': {'area': size},
              'children': [debug_sections, sections]}))
    return string


def process_iterator(proc) -> str:
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        yield line


def mode_nm_(iterator: Iterable, strip_prefix: str,
             cppfilt: Optional[str]) -> str:
    try:
        result = subprocess.run([cppfilt, 'main'], capture_output=True)
    except FileNotFoundError:
        print(f"Could not find c++filt at {cppfilt}, "
              "output won't be demangled.",
              file=sys.stderr)
        raise FileNotFoundError(f"Could not find c++filt at {cppfilt}, "
                                "output won't be demangled.")
    else:
        res = result.stdout
        if res.strip() != 'main':
            print(f"{cppfilt} failed demangling, "
                  "output won't be demangled.",
                  file=sys.stderr)
            cppfilt = None

    return dump_nm(iterator, strip_prefix=strip_prefix, cppfilt=cppfilt)


def mode_nm_cmd(path: str, strip_prefix: str, cppfilt: Optional[str]) -> str:
    cmd = ['nm', '-C', '-S', '-l', path]
    print(f"Running `{' '.join(cmd)}` can take several minutes")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, encoding='utf8')
    proc_it = process_iterator(proc)

    return mode_nm_(proc_it, strip_prefix=strip_prefix, cppfilt=cppfilt)


def mode_nm_file(path: str, strip_prefix: str, cppfilt: Optional[str]) -> str:
    with open(path, 'r') as file:
        return mode_nm_(file, strip_prefix=strip_prefix, cppfilt=cppfilt)


def mode_objdump_file(path: str) -> str:
    with open(path, 'r') as file:
        return dump_sections(file)


def mode_objdump_cmd(path: str) -> str:
    cmd = ['objdump', '-h', path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, encoding='utf8')
    proc_it = process_iterator(proc)

    return dump_sections(proc_it)


def mode_dump(path: str, filter: Optional[str]):
    cmd = ['nm', '-C', '-S', '-l', path]
    print(f"Running `{' '.join(cmd)}` can take several minutes")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, encoding='utf8')
    proc_it = process_iterator(proc)

    syms = list(parse_nm(proc_it))
    # a list of (sym, type, size, path); sort by size.
    syms.sort(key=lambda x: -x[2])
    total = 0
    for sym, type_, size, path in syms:
        if type_ in ('b', 'w'):
            continue  # skip bss and weak symbols
        if path is None:
            path = ''
        if filter and not (filter in sym or filter in path):
            continue
        print('%6s %s (%s) %s' % (format_bytes(size), sym,
                                  symbol_type_to_human(type_), path))
        total += size
    print('%6s %s' % (format_bytes(total), 'total'), end='')


if __name__ == '__main__':
    usage = """%(prog)s [options] MODE

    Modes are:
      nm:      uses nm to analyze the binary file
               output binary sections json suitable for a treemap
      dump:    uses nm to analyze the binary file, then,
               prints symbols sorted by size (pipe to head for best output)
      objdump: uses objdump to analyze the binary file
               output binary sections json suitable for a treemap"""

    parser = argparse.ArgumentParser(prog='bloat', usage=usage)
    parser.add_argument('format', choices=['nm', 'objdump'],
                        help='the format of the input is defined by')
    parser.add_argument('-i', '--input', action='store', dest='input_file',
                        metavar='PATH',
                        help='path to binary file with the input data')
    parser.add_argument('-o', '--output', action='store', dest='output_file',
                        metavar='PATH', default=None,
                        help=('json file to write the output to or '
                              '%(default)s (def) for sys.stdout'))
    parser.add_argument('-d', '--dump', action='store_true', dest='dump',
                        help='dump the output')
    parser.add_argument('--use-cmd-output', action='store_true',
                        dest='use_cmd',
                        help=("use the a file with the ouput of nm or objdump "
                              "instead of a binary file as input"))
    parser.add_argument('--strip-prefix', metavar='PATH', action='store',
                        help=('strip PATH prefix from paths; e.g. '
                              '/path/to/src/root'))
    parser.add_argument('--filter', action='store',
                        help='include only symbols/files matching FILTER')
    parser.add_argument('--c++filt', action='store', metavar='PATH',
                        dest='cppfilt', default='c++filt',
                        help=("Path to c++filt, used to demangle "
                              "symbols that weren't handled by nm. "
                              "Set to an invalid path to disable."))
    args = parser.parse_args()

    if not args.input_file or not os.path.isfile(args.input_file):
        raise FileNotFoundError(f"`{args.input_file}` could not be found")

    if args.dump and args.use_cmd_output:
        raise ValueError('--dump and --use-cmd-output cannot be set together')

    json_ = ''
    mode = args.format
    if mode == 'nm':
        if args.dump:
            mode_dump(args.input_file, args.filter)
        elif args.use_cmd:
            json_ = mode_nm_file(args.input_file, args.strip_prefix,
                                 args.cppfilt)
        else:
            json_ = mode_nm_cmd(args.input_file, args.strip_prefix,
                                args.cppfilt)
    elif mode == 'objdump':
        if args.use_cmd:
            json_ = mode_objdump_file(args.input_file)
        else:
            json_ = mode_objdump_cmd(args.input_file)

    if json_:
        export(args.output_file, json_)
