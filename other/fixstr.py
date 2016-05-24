from idaapi import *
from idc import *

def fix_puts(start=None, end=None):
    if start == None:
        start = GetFunctionAttr(here(), FUNCATTR_START)
        end = FindFuncEnd(start)

    ea = start
    while True:
        if 'call    puts' in GetDisasm(ea):
            str_addr = PrevHead(ea) + 1
            PatchDword(str_addr, Dword(str_addr) - 0x100)
        ea = NextHead(ea)
        if ea > end:
            break

def fix_strcmp(start=None, end=None):
    if start == None:
        start = GetFunctionAttr(here(), FUNCATTR_START)
        end = FindFuncEnd(start)

    ea = start
    while True:
        if 'call    strcmp' in GetDisasm(ea):
            str_addr = PrevHead(PrevHead(ea)) + 1
            PatchDword(str_addr, Dword(str_addr) - 0x100)
        ea = NextHead(ea)
        if ea > end:
            break

def fix_printf(start=None, end=None):
    if start == None:
        start = GetFunctionAttr(here(), FUNCATTR_START)
        end = FindFuncEnd(start)

    ea = start
    while True:
        if 'call    printf' in GetDisasm(ea):
            str_addr = PrevHead(PrevHead(ea)) + 1
            PatchDword(str_addr, Dword(str_addr) - 0x100)
        ea = NextHead(ea)
        if ea > end:
            break
