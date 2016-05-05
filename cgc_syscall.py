import idaapi
import idautils
import idc
import re

debug = False

syscall_table = {
    1: '_terminate',
    2: 'transmit',
    3: 'receive',
    4: 'fdwait',
    5: 'allocate',
    6: 'deallocate',
    7: 'random'
}

# get instruction range
for s in idautils.Segments():
    if idc.SegName(s) == '.text':
        start_ea = idc.SegStart(s)
        end_ea = idc.SegEnd(s)

if debug:
    print 'Start: {}, End: {}'.format(hex(start_ea).strip('L'), hex(end_ea).strip('L'))

# visit all instructions and fix comment for syscall instruction
eax = -1
ip = start_ea
while ip < end_ea and ip != idaapi.BADADDR:
    if 'int' in idc.GetMnem(ip) and '80h' == idc.GetOpnd(ip, 0):
        if eax != -1:
            idc.MakeComm(ip, 'CGC syscall: {}'.format(syscall_table[eax]))
    elif 'mov' in idc.GetMnem(ip) and 'eax' == idc.GetOpnd(ip, 0) and 5 == idc.GetOpType(ip, 1):
        value = idc.GetOpnd(ip, 1)
        if re.search('^[0-9]+$', value) != None:
            eax = int(value)
        if eax > 7 or eax < 1:
            eax = -1
        
    ip = idc.NextHead(ip)
