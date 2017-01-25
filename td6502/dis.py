# -*- coding: utf-8 -*-


from .op import Op
from . import util


def _hex_dollar(value, size):
    fmt = "${{:0{}X}}".format(2 * size)
    return fmt.format(value)

def _disp_str(disp):
    return "{:+d}".format(disp) if disp else ""

def _operand(addr, operand):
    return operand


class MD6502Dis:
    _FMTS = {
        Op.Mode.NONE : "",
        Op.Mode.IM   : "#{}",
        Op.Mode.ZP   : "{}",
        Op.Mode.ZPX  : "{},x",
        Op.Mode.ZPY  : "{},y",
        Op.Mode.AB   : "{}",
        Op.Mode.ABX  : "{},x",
        Op.Mode.ABY  : "{},y",
        Op.Mode.IX   : "({},x)",
        Op.Mode.IY   : "({}),y",
        Op.Mode.REL  : "{}",
        Op.Mode.IND  : "({})",
        Op.Mode.BRK  : "#{}",
    }

    def __init__(self):
        pass

    def dis(self, db, bank, out):
        prev_code = False
        prev_data = False

        addr = bank.org
        while bank.addr_contains(addr):
            label = db.get_label_by_addr(addr)
            if label and label.addr != addr:
                label = None

            if self._is_code(db, bank, addr):
                if prev_data:
                    out.write("\n\n")

                if label:
                    out.write("{}:\n".format(label.name))

                op = Op.get(bank[addr])
                operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
                self._dis_code(db, addr, op, operand, out)

                next_ = addr + op.size
                prev_code = True
                prev_data = False
            else:
                if prev_code:
                    out.write("\n\n")

                if label:
                    out.write("{}:\n".format(label.name))

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
        fmt = MD6502Dis._FMTS[op.mode]

        if op.mode is Op.Mode.REL:
            value      = util.rel_target(addr, operand)
            value_size = 2
        else:
            value      = operand
            value_size = op.argsize

        if op.mode is Op.Mode.NONE:
            mne_operand = ""
        elif op.mode in (Op.Mode.IM, Op.Mode.BRK):
            mne_operand = fmt.format(_hex_dollar(value, value_size))
        else:
            base  = db.get_operand_base (addr, value)
            label = db.get_operand_label(addr, base)

            # displacement が適用された場合、非配列ラベルのみを使う
            if base != value:
                if label and label.size > 1:
                    label = None
                disp = value - base
            else:
                disp = base - label.addr if label else 0

            base_str = label.name if label else _hex_dollar(base, value_size)
            value_str = base_str + _disp_str(disp)
            mne_operand = fmt.format(value_str)

        return op.name + (" " + mne_operand if mne_operand else "")

    def _operand_str(self, addr, operand):
        pass

    def _dis_data(self, db, addr, byte, out):
        out.write("{:04X} : db ${:02X}\n".format(addr, byte))


