import traceback
from idaapi import *
from idautils import *
from idc import *
from elftools import *
import iddaautils as utils

class SymbolCollector:
    """Collect symbols from ida pro"""

    def __get_ida_symbols(self):
        symbols = []

        # func symbols
        start_ea, end_ea = utils.get_seg_range('.text')
        for ea in Functions():
            name = GetFunctionName(ea)
            if ea >= start_ea and ea < end_ea:
                if 'sub_' in name: # skip default
                    continue
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

        return symbols

    def get_symfile(self):
        try:
            with open(get_root_filename(), 'rb') as f:
                elf = ELF(f.read())

            symbols = self.__get_ida_symbols()
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

class PseudocodeCollector:
    """Collect pseudo code from ida pro"""
