import traceback
from idaapi import *
from idautils import *
from idc import *
from elftools import *
import utils
from hashlib import md5

class SymbolCollector:
    """Collect symbols from ida pro"""

    @staticmethod
    def get_symfile():
        try:
            with open(get_root_filename(), 'rb') as f:
                elf = ELF(f.read())

            symbols = []
            # func symbols
            start_ea, end_ea = utils.get_seg_range('.text')
            for ea in Functions():
                name = GetFunctionName(ea)
                if ea >= start_ea and ea < end_ea:
                    func = get_func(ea)
                    symbols.append(Symbol(name, SymTypes.STB_GLOBAL_FUNC, int(func.startEA), int(func.size()), SegName(ea)))

            # data symbols
            start_ea, end_ea = utils.get_seg_range('.rodata')
            ea = start_ea
            while ea < end_ea:
                name = get_ea_name(ea)
                if name != '':
                    symbols.append(Symbol(name, SymTypes.STB_GLOBAL_OBJ, ea, 10, SegName(ea)))
                ea = NextHead(ea)

            start_ea, end_ea = utils.get_seg_range('.bss')
            ea = start_ea
            while ea < end_ea:
                name = get_ea_name(ea)
                if name != '':
                    symbols.append(Symbol(name, SymTypes.STB_GLOBAL_OBJ, ea, 10, SegName(ea)))
                ea = NextHead(ea)

            elf.strip_symbols()

            # raw strtab
            strtab_raw = "\x00" + "\x00".join([sym.name for sym in symbols]) + "\x00"

            symtab = {
                "name"      : SHN_UNDEF,
                "type"      : SHTypes.SHT_SYMTAB,
                "flags"     : 0,
                "addr"      : 0,
                "offset"    : len(elf.binary) + (elf.sizeof_sh() * 2),
                "size"      : (len(symbols) + 1) * elf.sizeof_sym(),
                "link"      : elf.ElfHeader.e_shnum + 1, # index of SHT_STRTAB
                "info"      : 1,
                "addralign" : 4,
                "entsize"   : elf.sizeof_sym()
            }

            off_strtab = (len(elf.binary) + (elf.sizeof_sh() * 2) + (elf.sizeof_sym() * (len(symbols) + 1)))

            strtab = {
                "name"      : SHN_UNDEF,
                "type"      : SHTypes.SHT_STRTAB,
                "flags"     : 0,
                "addr"      : 0,
                "offset"    : off_strtab,
                "size"      : len(strtab_raw),
                "link"      : 0,
                "info"      : 0,
                "addralign" : 1,
                "entsize"   : 0
            }

            elf.ElfHeader.e_shnum += 2
            elf.write(0, elf.ElfHeader)
            elf.append_section_header(symtab)
            elf.append_section_header(strtab)

            # Local symbol - separator
            sym = {
                "name"  : 0,
                "value" : 0,
                "size"  : 0,
                "info"  : SymFlags.STB_LOCAL,
                "other" : 0,
                "shndx" : 0
            }
            elf.append_symbol(sym)

            # add symbols
            for s in symbols:
                sh_idx = elf.get_section_id(s.shname)
                if not sh_idx:
                    continue

                sym = {
                    "name"  : strtab_raw.index(s.name),
                    "value" : s.value,
                    "size"  : s.size,
                    "info"  : s.info,
                    "other" : 0,
                    "shndx" : sh_idx
                }

                elf.append_symbol(sym)

            # add symbol strings
            elf.binary.extend(str(strtab_raw))
            return elf.binary

        except:
            print traceback.format_exc()

class PseudoCodeCollector(object):
    """Collect pseudo code from ida pro"""

    def __init__(self):
        self.pseudo_code = dict()
        if init_hexrays_plugin():
            install_hexrays_callback(self.__collect_pseudo_code)

    def __collect_pseudo_code(self, event, *args):
        try:
            if event == idaapi.hxe_text_ready:
                func = GetFunctionName(args[0].cfunc.entry_ea)
                self.pseudo_code[func] = str(args[0].cfunc)
        except:
            traceback.print_exc()
        return 0

    def get_pseudo_code(self, func):
        if func not in self.pseudo_code.keys():
            return 'Decompile in IDA Pro first. Otherwise, IDA Pro will be stuck and crashed.'
        return self.pseudo_code[func]

    @staticmethod
    def get_local_type():
        local_type = dict()
        local_type['header'] = utils.PrintLocalTypes(','.join([str(i) for i in range(1, GetMaxLocalType())]), \
            utils.PDF_INCL_DEPS | utils.PDF_DEF_FWD | utils.PDF_DEF_BASE | utils.PDF_HEADER_CMT)

        decls = ''
        for i in xrange(1, GetMaxLocalType()):
            type_name = GetLocalTypeName(i)
            if not type_name:
                continue
            decls += '{} v{};\n'.format(type_name, md5(type_name).hexdigest())
        template = '#include "localtype.h"\n'
        template += '{decls}\n'
        template += 'int main() {{}}\n'
        local_type['source'] = template.format(decls=decls)
        return local_type
