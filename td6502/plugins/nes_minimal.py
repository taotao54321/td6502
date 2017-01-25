# -*- coding: utf-8 -*-

"""td6502 NES plugin (minimal)

* I/O レジスタ領域 ($2000-$4017) の実行禁止
* 書き込み専用レジスタの読み取り禁止
* 読み込み専用レジスタへの書き込み禁止
"""


def create(org, size, args):
    return _NesMinimal()


class _NesMinimal:
    def __init__(self): pass

    def update_db(self, db):
        db.add_label("PPU_CTRL",   0x2000)
        db.add_label("PPU_MASK",   0x2001)
        db.add_label("PPU_STATUS", 0x2002)
        db.add_label("OAM_ADDR",   0x2003)
        db.add_label("OAM_DATA",   0x2004)
        db.add_label("PPU_SCROLL", 0x2005)
        db.add_label("PPU_ADDR",   0x2006)
        db.add_label("PPU_DATA",   0x2007)
        db.add_label("OAM_DMA",    0x4014)

        db.add_label("APU_PULSE1",   0x4000, size=4)
        db.add_label("APU_PULSE2",   0x4004, size=4)
        db.add_label("APU_TRIANGLE", 0x4008, size=4)
        db.add_label("APU_NOISE",    0x400C, size=4)
        db.add_label("APU_DMC",      0x4010, size=4)
        db.add_label("APU_STATUS",   0x4015)
        db.add_label("APU_FRAME",    0x4017)

        db.add_label("CONTROLLER", 0x4016, size=2)

    def update_ops_valid(self, ops_valid): pass

    def update_perms(self, perms):
        # I/O registers are not executable
        for i in range(0x2000, 0x4017+1):
            perms[i].executable = False

        # write-only registers
        for i in range(0x2000, 0x3FFF+1, 8):
            perms[i+0].readable = False
            perms[i+1].readable = False
            perms[i+3].readable = False
            perms[i+5].readable = False
            perms[i+6].readable = False
        perms[0x4000].readable = False
        perms[0x4001].readable = False
        perms[0x4002].readable = False
        perms[0x4003].readable = False
        perms[0x4004].readable = False
        perms[0x4005].readable = False
        perms[0x4006].readable = False
        perms[0x4007].readable = False
        perms[0x4008].readable = False
        perms[0x400A].readable = False
        perms[0x400B].readable = False
        perms[0x400C].readable = False
        perms[0x400E].readable = False
        perms[0x400F].readable = False
        perms[0x4010].readable = False
        perms[0x4011].readable = False
        perms[0x4012].readable = False
        perms[0x4013].readable = False
        perms[0x4014].readable = False

        # read-only registers
        for i in range(0x2000, 0x3FFF+1, 8):
            perms[i+2].writable = False

        # $4009 and $400D are unused, but eventually accessed in memory-clearing loops
        # http://wiki.nesdev.com/w/index.php/2A03
