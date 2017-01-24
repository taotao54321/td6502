# -*- coding: utf-8 -*-


import collections.abc


class Permission:
    def __init__(self, readable, writable, executable):
        self.readable   = readable
        self.writable   = writable
        self.executable = executable


class Bank(collections.abc.Sequence):
    def __init__(self, body, org):
        if not body: raise ValueError("body empty")
        if not 0 <= org <= 0xFFFF: raise ValueError("addr out of range")
        if not 0 <= org+len(body)-1 <= 0xFFFF: raise ValueError("addr out of range")
        self.body = body
        self.org  = org

    def addr_max(self):
        return self.org + len(self.body) - 1

    def addr_contains(self, addr):
        return self.org <= addr <= self.addr_max()

    def __getitem__(self, key):
        if isinstance(key, int):
            if not self.addr_contains(key): raise IndexError()
            return self.body[key - self.org]
        elif isinstance(key, slice):
            start, stop, step = key.start, key.stop, key.step
            if not self.addr_contains(start): raise IndexError()
            if stop is not None and stop > self.addr_max()+1: raise IndexError()
            return self.body[start-self.org : stop-self.org : step]
        else:
            raise TypeError()

    def __len__(self):
        return len(self.body)


