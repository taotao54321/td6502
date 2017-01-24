#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import os.path
from importlib.machinery import SourceFileLoader
import traceback
import argparse

from . import Bank, Permission
from .op import Op
from .db import Database, Analysis
from .ana import Analyzer
from . import plugin
from . import util


ADDR_AUTO = -1

class ReadAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None: raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        # argparse.FileType for "-" doesn't work for "rb" mode
        # https://bugs.python.org/issue14156
        if values is sys.stdin:
            values = sys.stdin.buffer

        with values as in_:
            buf = in_.read()

        setattr(namespace, self.dest, buf)

class DatabaseAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None: raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        db = Database(0)
        with values as in_:
            try:
                db.apply_script(in_)
            except:
                parser.error(traceback.format_exc())

        setattr(namespace, self.dest, db)

class PluginAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None: raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        plugins = getattr(namespace, self.dest)

        path_args = values.split(":")
        if len(path_args) > 2: raise ValueError("plugin format error")
        path = path_args[0]
        args = [] if len(path_args) == 1 else path_args[1].split(",")

        plugins.append((path, args))

        #name = os.path.splitext(os.path.basename(path))[0]
        #module = SourceFileLoader(name, path).load_module()
        #plugins.append(module.create(args))

def addr16(str_):
    value = int(str_, base=0)
    if not 0 <= value <= 0xFFFF:
        raise argparse.ArgumentTypeError("invalid address: {}".format(str_))
    return value

def addr_interrupt(str_):
    if str_.lower() == "auto":
        return ADDR_AUTO
    else:
        return addr16(str_)

def parse_args():
    ap = argparse.ArgumentParser(description="td6502 analyzer")
    ap.add_argument("_buf", type=argparse.FileType("rb"), action=ReadAction, metavar="INFILE")
    ap.add_argument("--db", type=argparse.FileType("r"), action=DatabaseAction,
                    help="program database")
    ap.add_argument("--org", type=addr16,
                    help="origin address")
    ap.add_argument("--nmi", type=addr_interrupt,
                    help='NMI address ("auto": use interrupt vector)')
    ap.add_argument("--reset", type=addr_interrupt,
                    help='RESET address ("auto": use interrupt vector)')
    ap.add_argument("--irq", type=addr_interrupt,
                    help='IRQ address ("auto": use interrupt vector)')
    ap.add_argument("--plugin", action=PluginAction, dest="plugins", default=[], metavar="PLUGIN",
                    help="plugin (executed in the given order)")

    args = ap.parse_args()

    if args.db is None:
        if args.org is None: ap.error("origin not specified")
        args.db = Database(args.org)

    # --db と --org が両方指定された場合、後者を優先(使う場面はあまりないだろうが…)
    if args.org is not None:
        args.db.org = args.org

    if not args._buf: ap.error("input file is empty")
    args.bank = Bank(args._buf, args.db.org)

    # 必要に応じ割り込みベクタを見る
    if args.nmi == ADDR_AUTO:
        if not (args.bank.addr_contains(0xFFFA) and args.bank.addr_contains(0xFFFB)):
            ap.error("bank does not contain NMI vector")
        args.nmi = util.unpack_u(bank[0xFFFA:0xFFFB+1])
    if args.reset == ADDR_AUTO:
        if not (args.bank.addr_contains(0xFFFC) and args.bank.addr_contains(0xFFFD)):
            ap.error("bank does not contain RESET vector")
        args.reset = util.unpack_u(bank[0xFFFC:0xFFFD+1])
    if args.irq == ADDR_AUTO:
        if not (args.bank.addr_contains(0xFFFE) and args.bank.addr_contains(0xFFFF)):
            ap.error("bank does not contain IRQ vector")
        args.irq = util.unpack_u(bank[0xFFFE:0xFFFF+1])

    # 割り込みアドレスは NOTCODE 指定されてない限り CODE とする
    if args.nmi is not None:
        args.db.change_analysis(args.nmi, Analysis.UNKNOWN, Analysis.CODE)
    if args.reset is not None:
        args.db.change_analysis(args.reset, Analysis.UNKNOWN, Analysis.CODE)
    if args.irq is not None:
        args.db.change_analysis(args.irq, Analysis.UNKNOWN, Analysis.CODE)

    return args

def main():
    args = parse_args()

    ops_valid = [Op.get(code).official for code in range(0x100)]
    perms = [Permission(True, True, True) for _ in range(0x10000)]

    for plg_path, plg_args in args.plugins:
        plg_name = os.path.splitext(os.path.basename(plg_path))[0]
        plg_module = SourceFileLoader(plg_name, plg_path).load_module()
        plg = plg_module.create(args.db.org, len(args.bank), plg_args)
        plugin.exec_(plg, args.db, ops_valid, perms)

    analyzer = Analyzer()
    analyzer.analyze(args.db, args.bank, ops_valid, perms, args.irq)

    args.db.save_script(sys.stdout)

if __name__ == "__main__": main()
