import idaapi
import idautils
import idc

def __get_range(seg):
    # get instruction range
    for s in idautils.Segments():
        if idc.SegName(s) == seg:
            start_ea = idc.SegStart(s)
            end_ea = idc.SegEnd(s)

    debug = True
    if debug:
        print 'Start: {}, End: {}'.format(hex(start_ea).strip('L'), hex(end_ea).strip('L'))

    return start_ea, end_ea

def get_func_symbols(): 
    symbols = []
    start_ea, end_ea = __get_range('.text')
    for func in idautils.Functions():
        name = GetFunctionName(func)
        # normal function
        if func > start_ea and func < end_ea:
            if 'sub_' in name: # skip default
                continue
            symbols.append({name: func})
    return symbols

def get_data_symbols():
    symbols = []

    start_ea, end_ea = __get_range('.rodata')
    ea = start_ea
    while ea < end_ea:
        symbols.append(idaapi.get_ea_name(ea))
        ea = NextHead(ea)

    start_ea, end_ea = __get_range('.bss')
    ea = start_ea
    while ea < end_ea:
        symbols.append(idaapi.get_ea_name(ea))
        ea = NextHead(ea)

    return symbols

print get_data_symbols()
        
