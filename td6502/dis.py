# -*- coding: utf-8 -*-


from .op import Op
from .db import DataType
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
        prev_code      = False
        prev_data      = False
        prev_exitpoint = False

        addr = bank.org
        while bank.addr_contains(addr):
            code = self._is_code(db, bank, addr)

            # 非配列ラベルを取得
            label = db.get_label_by_addr(addr)
            if label and label.addr != addr:
                label = None

            # 以下の場合に空行挿入:
            #   * コード/データ境界
            #   * コード終端要素と非配列ラベルの境界
            # 「コード終端要素」とは、JMP abs / JMP ind / RTS / RTI を指す。
            #
            # 後者は一応ルーチン分割のつもりだが、完璧ではないと思われ
            # る。ただしこれは人手でやっても判然としないケースもあるの
            # で多少の誤りは許容する方向で。
            if (code and prev_data) or (not code and prev_code) or (prev_exitpoint and label):
                out.write("\n\n")

            comm = db.comments[addr]
            if comm.head is not None:
                out.write(comm.head_fmt())
                out.write("\n")

            if label:
                out.write("{}:\n".format(label.name))

            if code:
                op = Op.get(bank[addr])
                operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
                self._dis_code(db, addr, op, operand, out)

                next_ = addr + op.size
                prev_exitpoint = op.code in (0x4C, 0x6C, 0x40, 0x60)
            else:
                data_type = db.data_types[addr]
                data_size = data_type.size

                # 尻切れになる場合は Byte 単位で出力
                if not bank.addr_contains(addr + data_size - 1):
                    data_size = 1
                    self._dis_data_byte(db, addr, bank[addr], out)
                else:
                    data_buf = bank[addr:addr+data_size]
                    self._dis_data(db, addr, data_type, data_buf, out)

                next_ = addr + data_size
                prev_exitpoint = False

            if comm.tail is not None:
                out.write(" " + comm.tail_fmt())
            out.write("\n")

            addr = next_
            prev_code = code
            prev_data = not code

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

        out.write("{:04X} : {:<12}{}".format(addr, raw, mne))

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

            # displacement が適用された場合、アドレスが base と一致するラベルのみを使う
            if base != value:
                if label and label.addr != base:
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

    def _dis_data(self, db, addr, type_, buf, out):
        if type_ is DataType.BYTE:
            self._dis_data_byte(db, addr, buf[0], out)
        elif type_ is DataType.WORD:
            value = util.unpack_u(buf)
            self._dis_data_word(db, addr, value, out)
        else:
            assert False # NOTREACHED

    def _dis_data_word(self, db, addr, value, out):
        base  = db.get_operand_base (addr, value)
        label = db.get_operand_label(addr, base)

        # displacement が適用された場合、アドレスが base と一致するラベルのみを使う
        if base != value:
            if label and label.addr != base:
                label = None
            disp = value - base
        else:
            disp = base - label.addr if label else 0

        # WORD 出力で常にラベルを使うべきかどうかは微妙だけどとりあえず…
        base_str = label.name if label else _hex_dollar(base, 2)
        value_str = base_str + _disp_str(disp)

        out.write("{:04X} : dw {}".format(addr, value_str))

    def _dis_data_byte(self, db, addr, value, out):
        # BYTE の場合は displacement やラベルは考慮しない
        out.write("{:04X} : db ${:02X}".format(addr, value))


