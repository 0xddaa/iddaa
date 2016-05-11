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

class CGCHelper:
    def __use_libcgc(self):
        return True

    def __get_inst_range(self):
        # get instruction range
        for s in idautils.Segments():
            if idc.SegName(s) == '.text':
                start_ea = idc.SegStart(s)
                end_ea = idc.SegEnd(s)

        if debug:
            print 'Start: {}, End: {}'.format(hex(start_ea).strip('L'), hex(end_ea).strip('L'))

        return start_ea, end_ea

    def revise_syscall(self):
        # visit all instructions
        start_ea, end_ea = self.__get_inst_range()
        eax = -1
        ip = start_ea
        while ip < end_ea and ip != idaapi.BADADDR:
            if 'int' in idc.GetMnem(ip) and '80h' == idc.GetOpnd(ip, 0):
                if eax != -1:
                    # fix comment and function name
                    idc.MakeComm(ip, 'CGC syscall: {}'.format(syscall_table[eax]))
                    if self.__use_libcgc():
                        idc.MakeName(idc.GetFunctionAttr(ip, FUNCATTR_START), syscall_table[eax])
            elif 'mov' in idc.GetMnem(ip) and 'eax' == idc.GetOpnd(ip, 0) and 5 == idc.GetOpType(ip, 1):
                value = idc.GetOpnd(ip, 1)
                if re.search('^[0-9]+$', value) != None:
                    eax = int(value)
                if eax > 7 or eax < 1:
                    eax = -1

            ip = idc.NextHead(ip)

cgc_helper = CGCHelper()
