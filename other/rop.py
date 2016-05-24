from idaapi import *
from idc import *
import re

gadgets = []

def find_gadget(n = 4):
    start = 0x400260
    end = 0x4932b0

    gadget = ''
    for ea in xrange(start, end):
        if not re.search('^retn$', GetDisasm(ea)):
            continue

        gadget = '; {}'.format(GetDisasm(ea))
        tmp = ea
        for i in xrange(n):
            tmp = PrevHead(tmp)
            gadget = '; {}'.format(GetDisasm(tmp)) + gadget
        gadget = gadget[2:]
        gadgets.append({hex(ea): gadget)

def find_syscall_ret():
    for g in gadgets:
        if re.search('syscall.*retn', g):
            print g
