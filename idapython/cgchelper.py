import idaapi
import iddaa.utils as utils
import idc
import re

debug = False
version = (1, 0, 0)

syscall_table = {
    1: '_terminate',
    2: 'transmit',
    3: 'receive',
    4: 'fdwait',
    5: 'allocate',
    6: 'deallocate',
    7: 'random'
}

class CGCHelper(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = 'CGC Helper'
    help = 'Press Shift-R to revise syscall to CGC defined.' 
    wanted_name = 'CGC Helper'
    wanted_hotkey = ''

    def init(self):
        print('CGC Helper ({}) plugin has been loaded.'.format(utils.dump_version(version)))
        hotkey_ctx = idaapi.add_hotkey('Shift-R', CGCHelper.revise_syscall)
        if hotkey_ctx:
            print(self.help)
            return idaapi.PLUGIN_KEEP
        else:
            print('Failed to register CGCHelper hotkey!')
            del hotkey_ctx
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass

    @staticmethod
    def revise_syscall(rename=False):
        if not rename:
            print('Change the function name with `CGCHeler.revise_syscall(True)`.')

        # visit all instructions
        start_ea, end_ea = utils.get_seg_range('.text')
        eax = -1
        ip = start_ea
        while ip < end_ea and ip != idaapi.BADADDR:
            if 'int' in idc.GetMnem(ip) and '80h' == idc.GetOpnd(ip, 0):
                if eax != -1:
                    # fix comment and function name
                    print('{}: {}'.format(hex(ip), syscall_table[eax]))
                    idc.MakeComm(ip, 'CGC syscall: {}'.format(syscall_table[eax]))
                    if rename:
                        print('Change {} to {}'.format(idc.GetFunctionName(ip), syscall_table[eax]))
                        idc.MakeName(idc.GetFunctionAttr(ip, idc.FUNCATTR_START), syscall_table[eax])
            elif 'mov' in idc.GetMnem(ip) and 'eax' == idc.GetOpnd(ip, 0) and 5 == idc.GetOpType(ip, 1):
                value = idc.GetOpnd(ip, 1)
                if re.search('^[0-9]+$', value) != None:
                    eax = int(value)
                if eax > 7 or eax < 1:
                    eax = -1

            ip = idc.NextHead(ip)

def PLUGIN_ENTRY():
    return CGCHelper()
