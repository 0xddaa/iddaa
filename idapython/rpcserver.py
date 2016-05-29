import socket
import thread
import cPickle
from iddaa.gdbsync import SymbolCollector, PseudoCodeCollector

debug = False
version = (1, 0, 0)
port = 56746

class RPCServer(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = 'IDA RPC for remote gdb'
    help = ''
    wanted_name = 'RPC Server'
    wanted_hotkey = ''

    def init(self):
        print('RPC Server ({}) plugin has been loaded.'.format(utils.dump_version(version)))
        thread.start_new_thread(RPCServer.__init_socket_server, ())
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass

    @staticmethod
    def __init_socket_server():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, msg:
            sys.stderr.write("[ERROR] %s\n" % msg[1])
            sys.exit(1)

        print('Start RPCServer at localhost:{} ...'.format(port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        sock.listen(5)

        while True:
            (csock, adr) = sock.accept()
            cmd = csock.recv(1024).strip()
            if cmd == 'GETSYM':
                csock.send(SymbolCollector.get_symfile())
            elif 'GETPSEUDOCODE' in cmd:
                if len(cmd.split(' ')) < 2:
                    csock.send('Miss function name.')
                    continue
                func = cmd.split(' ')[1]
                csock.send(PseudoCodeCollector.get_pseudo_code(func))
            elif 'GETLOCALTYPE' in cmd:
                csock.send(cPickle.dumps(PseudoCodeCollector.get_local_type()))
            csock.close()

def PLUGIN_ENTRY():
    return RPCServer()
