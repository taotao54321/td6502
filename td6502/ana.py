# -*- coding: utf-8 -*-


from .op import Op
from .db import Analysis
from . import util


_UNKNOWN = Analysis.UNKNOWN
_CODE    = Analysis.CODE
_NOTCODE = Analysis.NOTCODE


def _not_executable(db, perms, addr):
    return db.is_notcode(addr) or not perms[addr].executable

def _access_illegal(db, perms, addr, op):
    if op.argread  and not perms[addr].readable:         return True
    if op.argwrite and not perms[addr].writable:         return True
    if op.argexec  and _not_executable(db, perms, addr): return True
    return False

def _abi_addrs(addr):
    """abx, aby の全アドレス候補を返す(dummy read は考慮しない)。
    """
    for _ in range(0x100):
        yield addr
        addr = util.addr_add(addr, 1)

def _op_nexts(addr, op, operand, irq):
    """命令 op 実行後の飛び先の候補を全て返す。候補数は 0,1,2 のいずれか。

    候補数1の場合のみ飛び先が特定できないことがある。その場合飛び先を
    None で表す。
    """
    # KIL
    if op.code in (0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x92, 0xB2, 0xD2, 0xF2):
        return ()
    # BRK
    elif op.code == 0x00:
        return (irq,)
    # JSR, JMP abs
    elif op.code in (0x20, 0x4C):
        return (operand,)
    # JMP ind, RTS, RTI
    elif op.code in (0x6C, 0x60, 0x40):
        return (None,)
    # 分岐命令
    elif op.mode is Op.Mode.REL:
        after  = addr + 2
        target = addr + 2 + util.u8_to_s8(operand)

        # アドレス空間内で wrap around するケースはどう扱うべきか判然
        # としないので、とりあえず飛び先なしとして判定を打ち切る
        if after > 0xFFFF or target < 0 or target > 0xFFFF:
            return ()

        return tuple({ after, target }) # 一致するケースがありうるので
    # その他
    else:
        after = addr + op.size

        # アドレス空間内で wrap around するケースはどう扱うべきか判然
        # としないので、とりあえず飛び先なしとして判定を打ち切る
        if after > 0xFFFF:
            return ()

        return (after,)


class Analyzer:
    def __init__(self):
        pass

    def analyze(self, db, bank, ops_valid, perms, irq):
        """コードを解析し、プログラムデータベースを更新する。

        db: プログラムデータベース
        bank: バンク
        ops_valid: オペコードの有効/無効 (0x100 要素の bool 配列)
        perms: アドレスごとのパーミッション (0x10000 要素の Permission 配列)
        irq: IRQ 割り込みアドレス (None: 指定なし)
        """
        # pass 1: 命令単位のコード判定
        self._analyze_single(db, bank, ops_valid, perms, irq)

        # pass 2: 制御フローを考慮したコード判定
        self._analyze_flow(db, bank, irq)

    def _analyze_single(self, db, bank, ops_valid, perms, irq):
        """命令単位のコード判定(制御フローを考慮しない)。

        有効オペコード、およびアドレスごとの読み/書き/実行パーミッショ
        ンに基づく判定。

        UNKNOWN -> NOTCODE の変化のみが起こりうる。

        バンク内のオペコード/オペランドのフェッチ、およびオペコードの
        実行は暗黙的に許可されているとみなす。
        """
        for addr in range(bank.org, bank.addr_max()+1):
            if not db.is_unknown(addr): continue

            op = Op.get(bank[addr])

            # 無効オペコードは即 NOTCODE
            if not ops_valid[op.code]:
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
                continue

            # 有効オペコードの場合、まず尻切れになってたら放置
            if not bank.addr_contains(addr + op.size - 1):
                continue

            # 尻切れでない有効オペコードはオペランドを見て判定
            operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
            self._analyze_single_perm(db, addr, op, operand, perms, irq)

    def _analyze_single_perm(self, db, addr, op, operand, perms, irq):
        """アドレスごとのパーミッションに基づくコード判定。

        _analyze_single() の下請け。
        """
        # BRK
        if op.mode is Op.Mode.BRK and irq is not None:
            if _not_executable(db, perms, irq) or not perms[irq].readable:
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
        # 分岐命令
        elif op.mode is Op.Mode.REL:
            target = util.rel_target(addr, operand)
            if _not_executable(db, perms, target) or not perms[target].readable:
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
        # JMP ind
        # ページまたぎ時は wrap around することに注意
        # http://www.6502.org/tutorials/6502opcodes.html#JMP
        elif op.code == 0x6C:
            hi = (operand & 0xFF00) | ((operand+1) & 0xFF)
            if not perms[operand].readable or not perms[hi].readable:
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
        # zp, abs
        elif op.mode in (Op.Mode.ZP, Op.Mode.AB):
            if _access_illegal(db, perms, operand, op):
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
        # zpx, zpy, ix
        # レジスタの値域解析まではやらないのでゼロページ全体をチェック
        # (zpx, zpy, ix はページまたぎ時に wrap around する)
        # http://wiki.nesdev.com/w/index.php/CPU_addressing_modes
        elif op.mode in (Op.Mode.ZPX, Op.Mode.ZPY, Op.Mode.IX):
            if all(_access_illegal(db, perms, i, op) for i in range(0xFF+1)):
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
        # abx, aby
        # レジスタの値域解析まではやらないので候補アドレス全てをチェック
        # とりあえずページまたぎ時の dummy read は考慮しない
        # http://wiki.nesdev.com/w/index.php/CPU_addressing_modes
        elif op.mode in (Op.Mode.ABX, Op.Mode.ABY):
            if all(_access_illegal(db, perms, i, op) for i in _abi_addrs(operand)):
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)
        # iy
        # ポインタ取得時のページまたぎは wrap around する
        # http://wiki.nesdev.com/w/index.php/CPU_addressing_modes
        elif op.mode is Op.Mode.IY:
            hi = (operand+1) & 0xFF
            if not perms[operand].readable or not perms[hi].readable:
                db.change_analysis(addr, _UNKNOWN, _NOTCODE)

    def _analyze_flow(self, db, bank, irq):
        self._analyze_flow_unknown(db, bank, irq)
        self._analyze_flow_code(db, bank, irq)

    def _analyze_flow_unknown(self, db, bank, irq):
        done = 0x10000 * [False]
        for addr in range(0x10000):
            if not bank.addr_contains(addr): continue
            if not db.is_unknown(addr): continue
            if done[addr]: continue

            self._analyze_flow_unknown_one(db, bank, irq, addr, done, [])

    def _analyze_flow_unknown_one(self, db, bank, irq, addr, done, trace):
        # return で探索打ち切り
        # break でトレースした制御フローを NOTCODE として終了
        while True:
            if not bank.addr_contains(addr): return
            if done[addr]: return
            done[addr] = True
            trace.append(addr)

            op = Op.get(bank[addr])
            # 命令が尻切れになっていたら探索打ち切り
            if not bank.addr_contains(addr + op.size - 1): return

            operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
            nexts = _op_nexts(addr, op, operand, irq)
            # 次の飛び先がなければ探索打ち切り
            if not nexts: return

            if len(nexts) == 1:
                next_ = nexts[0]
                # 特定不可アドレスはどうしようもないので探索打ち切り
                if next_ is None: return

                if db.is_unknown(next_):
                    addr = next_ # 探索続行
                elif db.is_code(next_):
                    return
                elif db.is_notcode(next_):
                    break
            elif len(nexts) == 2:
                if db.is_unknown(nexts[0]) and db.is_unknown(nexts[1]):
                    # 両方探索
                    self._analyze_flow_unknown_one(db, bank, irq, nexts[0], done, [])
                    self._analyze_flow_unknown_one(db, bank, irq, nexts[1], done, [])
                    if db.is_notcode(nexts[0]) and db.is_notcode(nexts[1]):
                        break
                    return
                elif db.is_code(nexts[0]) or db.is_code(nexts[1]):
                    return
                elif db.is_unknown(nexts[0]) and db.is_notcode(nexts[1]):
                    addr = nexts[0] # 探索続行
                elif db.is_notcode(nexts[0]) and db.is_unknown(nexts[1]):
                    addr = nexts[1] # 探索続行
                elif db.is_notcode(nexts[0]) and db.is_notcode(nexts[1]):
                    break
            else:
                assert False # NOTREACHED

        for addr in trace:
            db.change_analysis(addr, _UNKNOWN, _NOTCODE)

    def _analyze_flow_code(self, db, bank, irq):
        done = 0x10000 * [False]
        for addr in range(0x10000):
            if not bank.addr_contains(addr): continue
            if not db.is_code(addr): continue
            if done[addr]: continue

            self._analyze_flow_code_one(db, bank, irq, addr, done)

    def _analyze_flow_code_one(self, db, bank, irq, addr, done):
        while True:
            if not bank.addr_contains(addr): return
            if done[addr]: return
            done[addr] = True

            op = Op.get(bank[addr])
            # 命令が尻切れになっていたら探索打ち切り
            if not bank.addr_contains(addr + op.size - 1): return

            operand = util.unpack_u(bank[addr+1:addr+1+op.argsize]) if op.argsize else None
            nexts = _op_nexts(addr, op, operand, irq)
            # 次の飛び先がなければ探索打ち切り
            if not nexts: return

            if len(nexts) == 1:
                next_ = nexts[0]
                # 特定不可アドレスはどうしようもないので探索打ち切り
                if next_ is None: return

                if db.is_unknown(next_):
                    db.change_analysis(next_, _UNKNOWN, _CODE)
                    addr = next_ # 探索続行
                elif db.is_code(next_):
                    addr = next_ # 探索続行
                elif db.is_notcode(next_):
                    return
            elif len(nexts) == 2:
                if db.is_unknown(nexts[0]) and db.is_notcode(nexts[1]):
                    db.change_analysis(nexts[0], _UNKNOWN, _CODE)
                    addr = nexts[0] # 探索続行
                elif db.is_notcode(nexts[0]) and db.is_unknown(nexts[1]):
                    db.change_analysis(nexts[1], _UNKNOWN, _CODE)
                    addr = nexts[1] # 探索続行
                else:
                    return
            else:
                assert False # NOTREACHED


