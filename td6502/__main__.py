#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import traceback
import argparse

from . import Bank, Permission
from .op import Op
from .db import Database, Analysis
from .ana import Analyzer
from .dis import MD6502Dis
from .plugin import Plugin
from . import util


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

def addr16(str_):
    value = int(str_, base=0)
    if not 0 <= value <= 0xFFFF:
        raise argparse.ArgumentTypeError("invalid address: {}".format(str_))
    return value


#---------------------------------------------------------------------
# analyzer
#---------------------------------------------------------------------

ADDR_AUTO = -1

class PluginAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None: raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        plugins = getattr(namespace, self.dest)

        identifier_args = values.split(":")
        if len(identifier_args) > 2: raise ValueError("plugin format error")
        identifier = identifier_args[0]
        args       = [] if len(identifier_args) == 1 else identifier_args[1].split(",")

        plugins.append((identifier, args))

def addr_interrupt(str_):
    if str_.lower() == "auto":
        return ADDR_AUTO
    else:
        return addr16(str_)

def ana_parse_args():
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
        args.nmi = util.unpack_u(args.bank[0xFFFA:0xFFFB+1])
    if args.reset == ADDR_AUTO:
        if not (args.bank.addr_contains(0xFFFC) and args.bank.addr_contains(0xFFFD)):
            ap.error("bank does not contain RESET vector")
        args.reset = util.unpack_u(args.bank[0xFFFC:0xFFFD+1])
    if args.irq == ADDR_AUTO:
        if not (args.bank.addr_contains(0xFFFE) and args.bank.addr_contains(0xFFFF)):
            ap.error("bank does not contain IRQ vector")
        args.irq = util.unpack_u(args.bank[0xFFFE:0xFFFF+1])

    # 割り込みアドレスは NOTCODE 指定されてない限り CODE とする
    if args.nmi is not None:
        args.db.change_analysis(args.nmi, Analysis.UNKNOWN, Analysis.CODE)
    if args.reset is not None:
        args.db.change_analysis(args.reset, Analysis.UNKNOWN, Analysis.CODE)
    if args.irq is not None:
        args.db.change_analysis(args.irq, Analysis.UNKNOWN, Analysis.CODE)

    return args

def ana_main():
    args = ana_parse_args()

    ops_valid = [Op.get(code).official for code in range(0x100)]
    perms     = [Permission(True, True, True) for _ in range(0x10000)]

    for plg_identifier, plg_args in args.plugins:
        plg = Plugin(plg_identifier, plg_args, args.db.org, len(args.bank))
        plg.exec_(args.db, ops_valid, perms)

    analyzer = Analyzer()
    analyzer.analyze(args.db, args.bank, ops_valid, perms, args.irq)

    args.db.save_script(sys.stdout)


#---------------------------------------------------------------------
# disassembler
#---------------------------------------------------------------------

FMT_MAP = {
    #"ca65"   : CA65Dis,
    "md6502" : MD6502Dis,
}

def dis_parse_args():
    ap = argparse.ArgumentParser(description="6502 disassembler")
    ap.add_argument("_buf", type=argparse.FileType("rb"), action=ReadAction, metavar="INFILE")
    ap.add_argument("--db", type=argparse.FileType("r"), action=DatabaseAction,
                    help="program database")
    ap.add_argument("--org", type=addr16,
                    help="origin address")
    ap.add_argument("--fmt", type=str, choices=sorted(FMT_MAP), default="md6502",
                    help="output format")

    args = ap.parse_args()

    if args.db is None:
        if args.org is None: ap.error("origin not specified")
        args.db = Database(args.org)

    # --db と --org が両方指定された場合、後者を優先(使う場面はあまりないだろうが…)
    if args.org is not None:
        args.db.org = args.org

    if not args._buf: ap.error("input file is empty")
    args.bank = Bank(args._buf, args.db.org)

    return args

def dis_main():
    args = dis_parse_args()

    dis = FMT_MAP[args.fmt]()
    dis.dis(args.db, args.bank, sys.stdout)
