# -*- coding: utf-8 -*-


import enum


def _chk_addr(addr):
    if not 0 <= addr <= 0xFFFF: raise ValueError("addr out of range")


class Analysis(enum.Enum):
    UNKNOWN = 1
    CODE    = 2
    NOTCODE = 3


class Database:
    def __init__(self, org):
        _chk_addr(org)

        self.org = org

        self.analysis = [Analysis.UNKNOWN for _ in range(0x10000)]

    def is_unknown(self, addr):
        return self.analysis[addr] is Analysis.UNKNOWN

    def is_code(self, addr):
        return self.analysis[addr] is Analysis.CODE

    def is_notcode(self, addr):
        return self.analysis[addr] is Analysis.NOTCODE

    def change_analysis(self, addr, from_, to):
        if self.analysis[addr] is from_:
            self.analysis[addr] = to

    def apply_script(self, in_):
        script = in_.read()
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

    def exec_(self, script):
        exec(script, self._namespace())

    def _namespace(self):
        FUNCS = (
            "org",
            "code", "notcode",
        )
        return { name : getattr(self, name) for name in FUNCS }
