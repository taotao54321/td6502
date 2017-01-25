#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import traceback
import argparse

from . import Bank, Permission
from .op import Op
from .db import Database, Analysis, DataType
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
            script = in_.read()

        try:
            db.apply_script(script)
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

def interrupt_fetch(bank, addr):
    if bank.addr_contains(addr) and bank.addr_contains(addr+1):
        return util.unpack_u(bank[addr:addr+2])
    else:
        return None

def interrupt_register(db, name, addr):
    # NOTCODE 指定されてない限り CODE とし、ラベルが振られていなければ振る
    db.change_analysis(addr, Analysis.UNKNOWN, Analysis.CODE)
    if db.is_code(addr) and not db.get_label_by_addr(addr):
        db.add_label(name, addr)

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

    # 特に初期データベースでの指定がなければ割り込みベクタは全て WORD 指定
    if all(args.db.is_unknown(i) for i in range(0xFFFA, 0xFFFF+1)):
        args.db.set_data_type(0xFFFA, DataType.WORD)
        args.db.set_data_type(0xFFFC, DataType.WORD)
        args.db.set_data_type(0xFFFE, DataType.WORD)

    # 必要に応じ割り込みベクタを見る
    if args.nmi == ADDR_AUTO:
        args.nmi = interrupt_fetch(args.bank, 0xFFFA)
        if args.nmi is None:
            ap.error("bank does not contain NMI vector")
    if args.reset == ADDR_AUTO:
        args.reset = interrupt_fetch(args.bank, 0xFFFC)
        if args.reset is None:
            ap.error("bank does not contain RESET vector")
    if args.irq == ADDR_AUTO:
        args.irq = interrupt_fetch(args.bank, 0xFFFE)
        if args.irq is None:
            ap.error("bank does not contain IRQ vector")

    if args.nmi is not None:
        interrupt_register(args.db, "NMI", args.nmi)
    if args.reset is not None:
        interrupt_register(args.db, "RESET", args.reset)
    if args.irq is not None:
        interrupt_register(args.db, "IRQ", args.irq)

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
