# -*- coding: utf-8 -*-


from collections import namedtuple

from .op import Op
from . import util


def _operand(addr, operand):
    return operand


_OprFmt = namedtuple("_OprFmt", ("fmt", "conv"))


class MD6502Dis:
    _FORMATTERS = {
        Op.Mode.NONE : _OprFmt("",            lambda a,o: None),
        Op.Mode.IM   : _OprFmt("#${:02X}",    _operand),
        Op.Mode.ZP   : _OprFmt("${:02X}",     _operand),
        Op.Mode.ZPX  : _OprFmt("${:02X},x",   _operand),
        Op.Mode.ZPY  : _OprFmt("${:02X},y",   _operand),
        Op.Mode.AB   : _OprFmt("${:04X}",     _operand),
        Op.Mode.ABX  : _OprFmt("${:04X},x",   _operand),
        Op.Mode.ABY  : _OprFmt("${:04X},y",   _operand),
        Op.Mode.IX   : _OprFmt("(${:02X},x)", _operand),
        Op.Mode.IY   : _OprFmt("(${:02X}),y", _operand),
        Op.Mode.REL  : _OprFmt("${:04X}",     util.rel_target),
        Op.Mode.IND  : _OprFmt("(${:04X})",   _operand),
        Op.Mode.BRK  : _OprFmt("#${:02X}",    _operand),
    }

    def __init__(self):
        pass

    def dis(self, db, bank, out):
        addr = bank.org
        while bank.addr_contains(addr):
            if self._is_code(db, bank, addr):
                op = Op.get(bank[addr])
                operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
                self._dis_code(db, addr, op, operand, out)
                next_ = addr + op.size
            else:
                self._dis_data(db, addr, bank[addr], out)
                next_ = addr + 1

            addr = next_

    def _is_code(self, db, bank, addr):
        """コードとして出力すべきかどうかの判定。"""
        op = Op.get(bank[addr])

        # コードとして解釈すると尻切れになる場合データとする
        if not bank.addr_contains(addr + op.size - 1): return False

        # CODE 指定されていればコード
        if db.is_code(addr): return True

        # UNKNOWN の場合、official 命令ならコード
        if db.is_unknown(addr) and op.official: return True

        # その他の場合データとする
        return False

    def _dis_code(self, db, addr, op, operand, out):
        raw = "{:02X}".format(op.code)
        if op.argsize == 1:
            raw += " {:02X}".format(operand)
        elif op.argsize == 2:
            raw += " {:02X} {:02X}".format(operand & 0xFF, operand >> 8)

        out.write("{:04X} : {}\t\t{} ".format(addr, raw, op.name))

        fmter = MD6502Dis._FORMATTERS[op.mode]
        value = fmter.conv(addr, operand)
        out.write(fmter.fmt.format(value))
        out.write("\n")

    def _dis_data(self, db, addr, byte, out):
        out.write("{:04X} : db ${:02X}\n".format(addr, byte))


