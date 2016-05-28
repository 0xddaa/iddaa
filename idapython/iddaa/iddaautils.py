import socket
import thread
import cPickle
import idaapi
import idautils
import idc
import iddaapro

def get_seg_range(seg):
    for s in idautils.Segments():
        if idc.SegName(s) == seg:
            start_ea = idc.SegStart(s)
            end_ea = idc.SegEnd(s)
    return start_ea, end_ea

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

class GDBSync:
    def __init__(self, port=50216):
        self.port = port

    def start(self):
        thread.start_new_thread(self.__init_socket_server, ())

    def __init_socket_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, msg:
            sys.stderr.write("[ERROR] %s\n" % msg[1])
            sys.exit(1)
         
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.port))
        sock.listen(5)

        while True:
            (csock, adr) = sock.accept()
            cmd = csock.recv(1024).strip()
            if cmd == 'GETSYM':
                csock.send(iddaapro.SymbolCollector().get_symfile())
            elif 'GETPSEUDOCODE' in cmd:
                if len(cmd.split(' ')) < 2:
                    csock.send('Miss function name.')
                    continue
                func = cmd.split(' ')[1]
                csock.send(iddaapro.PseudoCodeCollector.get_pseudo_code(func))
            elif 'GETLOCALTYPE' in cmd:
                csock.send(cPickle.dumps(iddaapro.PseudoCodeCollector.get_local_type()))
            csock.close()
