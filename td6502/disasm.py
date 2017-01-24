#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import traceback
import argparse

from . import Bank
from .db import Database
from .dis import MD6502Dis


FMT_MAP = {
    #"ca65"   : CA65Dis,
    "md6502" : MD6502Dis,
}

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

def parse_args():
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

def main():
    args = parse_args()

    dis = FMT_MAP[args.fmt]()
    dis.dis(args.db, args.bank, sys.stdout)

if __name__ == "__main__": main()
