# -*- coding: utf-8 -*-

"""td6502 plugin

全命令を許可する(非公式命令含む)。
"""


def create(org, size, args):
    return _AllOp()


class _AllOp:
    def __init__(self): pass

    def update_db(self, db): pass

    def update_ops_valid(self, ops_valid):
        for code in range(0x100):
            ops_valid[code] = True

    def update_perms(self, perms): pass
