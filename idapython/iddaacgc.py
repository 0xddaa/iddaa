import idaapi
import iddaa.iddaautils as utils
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

class CGCHelper:
    def revise_syscall(self, rename=False):
        # visit all instructions
        start_ea, end_ea = utils.get_seg_range('.text')
        eax = -1
        ip = start_ea
        while ip < end_ea and ip != idaapi.BADADDR:
            if 'int' in idc.GetMnem(ip) and '80h' == idc.GetOpnd(ip, 0):
                if eax != -1:
                    # fix comment and function name
                    idc.MakeComm(ip, 'CGC syscall: {}'.format(syscall_table[eax]))
                    if rename:
                        idc.MakeName(idc.GetFunctionAttr(ip, idc.FUNCATTR_START), syscall_table[eax])
            elif 'mov' in idc.GetMnem(ip) and 'eax' == idc.GetOpnd(ip, 0) and 5 == idc.GetOpType(ip, 1):
                value = idc.GetOpnd(ip, 1)
                if re.search('^[0-9]+$', value) != None:
                    eax = int(value)
                if eax > 7 or eax < 1:
                    eax = -1

            ip = idc.NextHead(ip)

cgc_helper = CGCHelper()
