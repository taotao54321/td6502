# -*- coding: utf-8 -*-

def unpack_u(buf):
    value = 0
    for i, b in enumerate(buf):
        value |= b << (8*i)
    return value

def u8_to_s8(value):
    return value if value < 0x80 else value-0x100

def addr_add(addr, n):
    """16bitアドレス空間で addr に n を加えたアドレスを返す。n は負でもよい。"""
    # The modulo operator always yields a result with the same sign as
    # its second operand (or zero)
    # https://docs.python.org/3/reference/expressions.html
    return (addr + n) % 0x10000

def rel_target(addr, operand):
    return addr_add(addr, 2 + u8_to_s8(operand))


