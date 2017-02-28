# -*- coding: utf-8 -*-


import re
import enum


def _chk_addr(addr):
    if not 0 <= addr <= 0xFFFF: raise ValueError("addr out of range")

def _chk_disp(disp):
    if not -0xFFFF <= disp <= 0xFFFF: raise ValueError("disp out of range")

def _chk_name(name):
    if not name.isidentifier(): raise ValueError("invalid label name: {}".format(name))


class Analysis(enum.Enum):
    UNKNOWN = 1
    CODE    = 2
    NOTCODE = 3


class DataType(enum.Enum):
    BYTE = (1, 1)
    WORD = (2, 2)

    def __init__(self, id_, size):
        self.size = size


class Label:
    def __init__(self, name, addr, size=1):
        _chk_name(name)
        if not 0 <= addr <= 0xFFFF: raise ValueError("addr out of range")
        if size < 1: raise ValueError("size must be positive")
        if addr + size - 1 > 0xFFFF: raise ValueError("addr+size out of range")

        self.name = name
        self.addr = addr
        self.size = size

    def addrs(self):
        return range(self.addr, self.addr + self.size)

    def __lt__(self, other):
        return self.name < other.name

class _LabelTable:
    def __init__(self):
        self.clear()

    def has_label(self, name):
        return name in self._name_label

    def get_label(self, name):
        if not self.has_label(name): raise KeyError(name)

        return self._name_label[name]

    def get_label_by_addr(self, addr, prefer=None):
        """addr に対応するラベルを返す。

        一般的には対応ラベルが複数ありうるため、ヒントとしてラベル名
        prefer を与えることができる。prefer が指定され、かつ対応ラベル
        にそれが含まれる場合、その名前のラベルを返す。そうでない場合、
        非配列ラベルを優先して返す。

        ラベルが1つもない場合は None を返す。
        """
        labels = self._addr_labels[addr]
        if not labels: return None

        if prefer is not None:
            result = tuple(l for l in labels if l.name == prefer)
            # 見つからなくてもエラーにはしない(ラベルテーブル変更時に
            # 整合性を保つのが面倒なので)
            if result:
                return result[0]

        def prefer_nonarray(label):
            return (0, label) if label.size == 1 else (1, label)
        result = sorted(labels, key=prefer_nonarray)
        return result[0]

    def get_labels_by_addr(self, addr):
        return tuple(self._addr_labels[addr])

    def add(self, label):
        if self.has_label(label.name):
            self.remove(label.name)

        self._name_label[label.name] = label

        for addr in label.addrs():
            self._addr_labels[addr].append(label)

    def remove(self, name):
        label = self.get_label(name)

        for addr in label.addrs():
            labels = self._addr_labels[addr]
            labels = [l for l in labels if l.name != name]

        del self._name_label[name]

    def clear(self):
        self._name_label  = {}
        self._addr_labels = [[] for _ in range(0x10000)]

    def labels(self):
        return self._name_label.values()

OPERAND_LABEL_AUTO = 1
OPERAND_LABEL_NONE = 2

class _OperandHint:
    def __init__(self):
        self.disp = 0
        self.name = OPERAND_LABEL_AUTO


class Comment:
    def __init__(self):
        self._head = None
        self._tail = None

    @property
    def head(self):
        return self._head

    @head.setter
    def head(self, str_):
        self._head = str_

    @property
    def tail(self):
        return self._tail

    @tail.setter
    def tail(self, str_):
        if any(c in str_ for c in "\r\n"):
            raise ValueError("tail comment cannot contain newline chars")
        self._tail = str_

    def head_fmt(self, comm_char=";"):
        lines = self.head.rstrip().splitlines()
        return "\n".join(Comment._head_fmt_one(line, comm_char) for line in lines)

    @staticmethod
    def _head_fmt_one(line, comm_char):
        space_maybe = " " if line else ""
        return comm_char + space_maybe + line

    def tail_fmt(self, comm_char=";"):
        tail = self.tail.rstrip()
        space_maybe = " " if tail else ""
        return comm_char + space_maybe + tail


class Database:
    def __init__(self, org):
        _chk_addr(org)

        self.org = org

        self.analysis = [Analysis.UNKNOWN for _ in range(0x10000)]

        self.data_types = [DataType.BYTE for _ in range(0x10000)]

        self._label_table   = _LabelTable()
        self._operand_hints = tuple(_OperandHint() for _ in range(0x10000))

        self.comments = [Comment() for _ in range(0x10000)]


    def is_unknown(self, addr):
        return self.analysis[addr] is Analysis.UNKNOWN

    def is_code(self, addr):
        return self.analysis[addr] is Analysis.CODE

    def is_notcode(self, addr):
        return self.analysis[addr] is Analysis.NOTCODE

    def change_analysis(self, addr, from_, to):
        if self.analysis[addr] is from_:
            self.analysis[addr] = to

    def set_data_type(self, addr, type_):
        self.data_types[addr] = type_
        for addr in range(addr, addr + type_.size):
            self.analysis[addr] = Analysis.NOTCODE


    def get_label(self, name):
        return self._label_table.get_label(name)

    def get_label_by_addr(self, addr, prefer=None):
        return self._label_table.get_label_by_addr(addr, prefer)

    def get_labels_by_addr(self, addr):
        return self._label_table.get_labels_by_addr(addr)

    def add_label(self, name, addr, size=1):
        self._label_table.add(Label(name, addr, size))

    def remove_label(self, name):
        self._label_table.remove(name)

    def clear_labels(self):
        self._label_table.clear()


    def set_operand_disp(self, addr, disp):
        """アドレス addr のオペランドに対する displacement を設定。

        逆アセンブルの際、オペランドを (ある値) + (インデックス) で表
        現したいことがある。例えば:

          lda var+1,x   ; アドレスが1ずれている場合の補正
          dw routine-1  ; RTS Trick (https://wiki.nesdev.com/w/index.php/RTS_Trick)

        この関数でそのような指定ができる。disp はインデックスの値。例
        えば RTS Trick の場合 -1 を指定する。
        """
        self._operand_hints[addr].disp = disp

    def set_operand_label(self, addr, name):
        """アドレス addr のオペランドに対するラベル名を設定。

        逆アセンブルの際、オペランドが自動でラベル名に変換されるが、対
        応するラベルが複数あったり、ラベル名への変換を行いたくない場合
        がある。

        name にラベル名を指定するとそれが優先される(その名前の対応ラベ
        ルが見つからない場合はデフォルトの処理となる)。

        name に OPERAND_LABEL_NONE を指定するとラベル名への変換を行わ
        ない。

        name に OPERAND_LABEL_AUTO を指定するとデフォルトの処理となる。
        """
        self._operand_hints[addr].name = name

    def get_operand_base(self, addr, operand):
        """アドレス addr のオペランドに対するベースアドレスを返す。

        displacement を考慮してベースアドレスを算出する。ベースアドレ
        スが範囲外の値になる場合 operand をそのまま返す。
        """
        base = operand - self._operand_hints[addr].disp
        if not 0 <= base <= 0xFFFF: # 範囲外になる場合 displacement を無視
            return operand
        else:
            return base

    def get_operand_label(self, addr, operand):
        """アドレス addr のオペランドに対するラベルを返す。

        ラベルが見つからないか、OPERAND_LABEL_NONE が指定されている場
        合 None を返す。
        """
        name = self._operand_hints[addr].name
        if name == OPERAND_LABEL_NONE: return None

        prefer = name if name != OPERAND_LABEL_AUTO else None
        return self._label_table.get_label_by_addr(operand, prefer)


    def apply_script(self, script):
        DatabaseScript(self).exec_(script)

    def save_script(self, out):
        out.write("# -*- coding: utf-8 -*-\n")
        out.write("\n")

        out.write("org(0x{:04X})\n".format(self.org))
        out.write("\n")

        for addr in range(0x10000):
            if self.is_code(addr):
                out.write("code(0x{:04X})\n".format(addr))
        out.write("\n")

        for region in self._regions_notcode():
            if region[1] == 1:
                out.write("notcode(0x{:04X})\n".format(region[0]))
            else:
                max_ = region[0] + region[1] - 1
                out.write("notcode(0x{:04X}, max_=0x{:04X})\n".format(region[0], max_))
        out.write("\n")

        for addr, type_ in enumerate(self.data_types):
            if type_ is not DataType.BYTE:
                out.write("data(0x{:04X}, type_={})\n".format(addr, type_.name))
        out.write("\n")

        labels = sorted(self._label_table.labels(), key=lambda label: label.addr)
        for label in labels:
            if label.size == 1:
                out.write("label({}, 0x{:04X})\n".format(
                    repr(label.name), label.addr))
            else:
                out.write("label({}, 0x{:04X}, size={:d})\n".format(
                    repr(label.name), label.addr, label.size))
        out.write("\n")

        for addr, hint in enumerate(self._operand_hints):
            if hint.disp:
                out.write("operand_disp(0x{:04X}, {:d})\n".format(addr, hint.disp))
            if hint.name == OPERAND_LABEL_NONE:
                out.write("operand_label(0x{:04X}, OPERAND_LABEL_NONE)\n")
            elif hint.name != OPERAND_LABEL_AUTO:
                out.write("operand_label(0x{:04X}, {}\n".format(addr, repr(hint.name)))
        out.write("\n")

    def _regions_notcode(self):
        region = [None, 0] # base, size
        for addr in range(0x10000):
            if self.is_notcode(addr):
                if region[0] is None:
                    region = [addr, 0]
                region[1] += 1
            else:
                if region[0] is not None:
                    yield tuple(region)
                region[0] = None
        if region[0] is not None:
            yield tuple(region)


class DatabaseScript:
    def __init__(self, db):
        self.db = db

    def org(self, addr):
        _chk_addr(addr)

        self.db.org = addr

    def code(self, addr):
        _chk_addr(addr)

        self.db.analysis[addr] = Analysis.CODE

    def notcode(self, base, *, max_=None, size=1):
        _chk_addr(base)
        if max_ is None:
            if size < 1: raise ValueError("size must be positive")
            max_ = base + size - 1
        _chk_addr(max_)
        if max_ < base: raise ValueError("max_ < base")

        for addr in range(base, max_+1):
            self.db.analysis[addr] = Analysis.NOTCODE

    def data(self, base, type_=DataType.BYTE, *, max_=None, count=1):
        """NOTCODE 指定およびデータ型の指定。notcode() の上位互換的な関数。"""
        _chk_addr(base)
        if type_ not in DataType: raise TypeError("invalid data type")
        if max_ is None:
            if count < 1: raise ValueError("count must be positive")
            max_ = base + type_.size * count - 1
        _chk_addr(max_)
        if max_ < base: raise ValueError("max_ < base")
        if (max_ - base + 1) % type_.size: raise ValueError("indivisible")

        for addr in range(base, max_+1, type_.size):
            self.db.set_data_type(addr, type_)

    def label(self, name, base, *, max_=None, size=1):
        _chk_addr(base)
        if max_ is None:
            if size < 1: raise ValueError("size must be positive")
            max_ = base + size - 1
        _chk_addr(max_)
        if max_ < base: raise ValueError("max_ < base")

        self.db.add_label(name, base, size)

    def operand_disp(self, addr, disp):
        _chk_addr(addr)
        _chk_disp(disp)
        self.db.set_operand_disp(addr, disp)

    def operand_label(self, addr, name):
        _chk_addr(addr)
        if name not in (OPERAND_LABEL_AUTO, OPERAND_LABEL_NONE):
            _chk_name(name)
        self.db.set_operand_label(addr, name)

    def comment_head(self, addr, head):
        self.db.comments[addr].head = head

    def comment_tail(self, addr, tail):
        self.db.comments[addr].tail = tail

    def exec_(self, script):
        exec(script, self._namespace())

    def _namespace(self):
        FUNCS = (
            "org",
            "code", "notcode", "data",
            "label", "operand_disp", "operand_label",
            "comment_head", "comment_tail",
        )

        ns = { name : getattr(self, name) for name in FUNCS }

        ns["BYTE"] = DataType.BYTE
        ns["WORD"] = DataType.WORD
        ns["OPERAND_LABEL_AUTO"] = OPERAND_LABEL_AUTO
        ns["OPERAND_LABEL_NONE"] = OPERAND_LABEL_NONE

        return ns
