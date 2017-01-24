# -*- coding: utf-8 -*-


from .op import Op
from . import util


def _operand(addr, operand):
    return operand


class MD6502Dis:
    _FORMATTERS = {
        Op.Mode.NONE : ("",            lambda a,o: None),
        Op.Mode.IM   : ("#${:02X}",    _operand),
        Op.Mode.ZP   : ("${:02X}",     _operand),
        Op.Mode.ZPX  : ("${:02X},x",   _operand),
        Op.Mode.ZPY  : ("${:02X},y",   _operand),
        Op.Mode.AB   : ("${:04X}",     _operand),
        Op.Mode.ABX  : ("${:04X},x",   _operand),
        Op.Mode.ABY  : ("${:04X},y",   _operand),
        Op.Mode.IX   : ("(${:02X},x)", _operand),
        Op.Mode.IY   : ("(${:02X}),y", _operand),
        Op.Mode.REL  : ("${:04X}",     util.rel_target),
        Op.Mode.IND  : ("(${:04X})",   _operand),
        Op.Mode.BRK  : ("#${:02X}",    _operand),
    }

    def __init__(self):
        pass

    def dis(self, db, bank, out):
        prev_code = False
        prev_data = False

        addr = bank.org
        while bank.addr_contains(addr):
            if self._is_code(db, bank, addr):
                if prev_data:
                    out.write("\n\n")

                op = Op.get(bank[addr])
                operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
                self._dis_code(db, addr, op, operand, out)

                next_ = addr + op.size
                prev_code = True
                prev_data = False
            else:
                if prev_code:
                    out.write("\n\n")

                self._dis_data(db, addr, bank[addr], out)

                next_ = addr + 1
                prev_code = False
                prev_data = True

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
        raw = self._dump_op(op, operand)
        mne = self._mnemonic(db, addr, op, operand)

        out.write("{:04X} : {:<12}{}\n".format(addr, raw, mne))

    def _dump_op(self, op, operand):
        buf = bytes((op.code,))
        if op.argsize:
            buf += util.pack_u(operand, op.argsize)
        return " ".join("{:02X}".format(b) for b in buf)

    def _mnemonic(self, db, addr, op, operand):
        fmt, conv = MD6502Dis._FORMATTERS[op.mode]
        mne_operand = fmt.format(conv(addr, operand))
        return op.name + (" " + mne_operand if mne_operand else "")

    def _dis_data(self, db, addr, byte, out):
        out.write("{:04X} : db ${:02X}\n".format(addr, byte))


