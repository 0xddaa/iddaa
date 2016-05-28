import idaapi
import idautils
import idc

def get_seg_range(seg):
    for s in idautils.Segments():
        if idc.SegName(s) == seg:
            start_ea = idc.SegStart(s)
            end_ea = idc.SegEnd(s)
    return start_ea, end_ea

def dump_version(v):
    return 'v' + '.'.join(str(i) for i in v)

PDF_INCL_DEPS  = 0x1  # include dependencies
PDF_DEF_FWD    = 0x2  # allow forward declarations
PDF_DEF_BASE   = 0x4  # include base types: __int8, __int16, etc..
PDF_HEADER_CMT = 0x8  # prepend output with a descriptive comment
def PrintLocalTypes(ordinals, flags): # from lastest idapython
    """
    Print types in a format suitable for use in a header file

    @param ordinals: comma-separated list of type ordinals
    @param flags: combination of PDF_... constants or 0

    @return: string containing the type definitions
    """
    class def_sink(idaapi.text_sink_t):

        def __init__(self):
            idaapi.text_sink_t.__init__(self)
            self.text = ""

        def _print(self, defstr):
            self.text += defstr
            return 0

    sink = def_sink()
    py_ordinals = map(lambda l : int(l), ordinals.split(","))
    idaapi.print_decls(sink, idaapi.cvar.idati, py_ordinals, flags)

    return sink.text
