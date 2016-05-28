import socket
import thread
import cPickle
import idaapi
import idautils
import idc
import gdbsync

class RPC:
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
                csock.send(gdbsync.SymbolCollector().get_symfile())
            elif 'GETPSEUDOCODE' in cmd:
                if len(cmd.split(' ')) < 2:
                    csock.send('Miss function name.')
                    continue
                func = cmd.split(' ')[1]
                csock.send(gdbsync.PseudoCodeCollector.get_pseudo_code(func))
            elif 'GETLOCALTYPE' in cmd:
                csock.send(cPickle.dumps(gdbsync.PseudoCodeCollector.get_local_type()))
            csock.close()

def PLUGIN_ENTRY():
    RPC().start()
    return True
