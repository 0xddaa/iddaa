import socket
import thread
import cPickle
from idaapi import *
from idautils import *
from idc import *

import iddaapro

def get_seg_range(seg):
    for s in Segments():
        if idc.SegName(s) == seg:
            start_ea = idc.SegStart(s)
            end_ea = idc.SegEnd(s)
    return start_ea, end_ea

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
            elif cmd == 'GETPSEUDO':
                pass
            csock.close()
