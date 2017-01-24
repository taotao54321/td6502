# -*- coding: utf-8 -*-

"""td6502 NES mapper 0 plugin

* $4018-$7FFF への全アクセス禁止
* $8000-$FFFF への書き込み禁止

NES『ゴルフ』などは当該領域への空アクセスを行っているので注意
(http://taotao54321.hatenablog.com/entry/20101104/1288883483)
"""


def create(org, size, args):
    return _NesMapper0()


class _NesMapper0:
    def __init__(self): pass

    def update_db(self, db): pass
    def update_ops_valid(self, ops_valid): pass

    def update_perms(self, perms):
        for i in range(0x4018, 0x7FFF+1):
            perms[i].readable   = False
            perms[i].writable   = False
            perms[i].executable = False

        for i in range(0x8000, 0xFFFF+1):
            perms[i].writable = False
