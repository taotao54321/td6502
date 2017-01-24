# -*- coding: utf-8 -*-

"""td6502 FCEUX CDL plugin

Usage: --plugin=cdl_fceux:foo.cdl[,offset][,aggressive]

  offset:     offset in CDL file
  aggressive: treat data as NOTCODE (0:off, 1:on)
"""


import os.path

from td6502.db import Analysis


_UNKNOWN = Analysis.UNKNOWN
_CODE    = Analysis.CODE
_NOTCODE = Analysis.NOTCODE


def create(org, size, args):
    if len(args) < 1: raise Exception("Usage: cdl_fceux:foo.cdl[,offset][,aggressive]")
    path = args[0]
    offset = int(args[1], base=0) if len(args) > 1 else 0
    aggressive = bool(int(args[2])) if len(args) > 2 else False

    cdl_size_total = os.path.getsize(path)
    if offset < 0 or offset + size > cdl_size_total:
        raise Exception("cdl_fceux: invalid offset")

    with open(path, "rb") as in_:
        in_.seek(offset)
        cdl = in_.read(size)
    if len(cdl) != size: raise Exception("cdl_fceux: size mismatch") # just in case

    return _CdlFceux(cdl, aggressive)


class _CdlFceux:
    def __init__(self, cdl, aggressive):
        self.cdl        = cdl
        self.aggressive = aggressive

    def update_db(self, db):
        """FCEUX CDL に基づくコード判定。

        CDL 上でコードまたは間接呼び出しコードとされている領域の先頭を
        UNKNOWN -> CODE とする(FCEUX CDL はオペコードとオペランドを区
        別していないため、これが限界)。既に NOTCODE 指定されている箇所
        には手を付けない。

        aggressive モードがオンの場合、CDL 上でデータ(DPCM データ含む)
        とされている領域を UNKNOWN -> NOTCODE とする(既に CODE 指定さ
        れている箇所には手を付けない)。これは誤判定の可能性があること
        に注意(CDL 上でデータとされている箇所はコードと兼用になってい
        る可能性が否定できないため)。
        """
        in_code     = False
        in_code_ind = False
        for i, b in enumerate(self.cdl):
            code     = b & (1<<0)
            data     = b & (1<<1)
            code_ind = b & (1<<4)
            data_ind = b & (1<<5)
            pcm      = b & (1<<6)

            if self.aggressive:
                if (not code and not code_ind) and (data or data_ind or pcm):
                    db.change_analysis(db.org + i, _UNKNOWN, _NOTCODE)

            if code:
                if not in_code:
                    db.change_analysis(db.org + i, _UNKNOWN, _CODE)
                    in_code = True
            else:
                in_code = False

            if code_ind:
                if not in_code_ind:
                    db.change_analysis(db.org + i, _UNKNOWN, _CODE)
                    in_code_ind = True
            else:
                in_code_ind = False

    def update_ops_valid(self, ops_valid): pass
    def update_perms(self, perms): pass
