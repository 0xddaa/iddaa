import idaapi
import idautils
import idc
import socket, sys
from thread import *
import cPickle

def __get_range(seg):
    for s in idautils.Segments():
        if idc.SegName(s) == seg:
            start_ea = idc.SegStart(s)
            end_ea = idc.SegEnd(s)

    return start_ea, end_ea

def get_func_symbols(): 
    symbols = []
    start_ea, end_ea = __get_range('.text')
    for ea in idautils.Functions():
        name = GetFunctionName(ea)
        # normal function
        if ea >= start_ea and ea < end_ea:
            if 'sub_' in name: # skip default
                continue
            symbols.append({name: ea})

    return symbols

def get_data_symbols():
    symbols = []
    start_ea, end_ea = __get_range('.rodata')
    ea = start_ea
    while ea < end_ea:
        name = idaapi.get_ea_name(ea)
        if name != '':
            symbols.append({name: ea})
        ea = NextHead(ea)

    start_ea, end_ea = __get_range('.bss')
    ea = start_ea
    while ea < end_ea:
        name = idaapi.get_ea_name(ea)
        if name != '':
            symbols.append({name: ea})
        ea = NextHead(ea)

    return symbols

def transmit_symbol():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error, msg:
        sys.stderr.write("[ERROR] %s\n" % msg[1])
        sys.exit(1)
     
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 50216))
    sock.listen(5)
     
    while True:
        (csock, adr) = sock.accept()
        cmd = csock.recv(1024).strip()
        if 'GETFUNCSYM' in cmd:
            csock.send(cPickle.dumps(get_func_symbols()))
        elif 'GETDATASYM' in cmd:
            csock.send(cPickle.dumps(get_data_symbols()))
        elif 'GETALLSYM' in cmd:
            csock.send(cPickle.dumps(get_func_symbols() + get_data_symbols()))

start_new_thread(transmit_symbol, ())
