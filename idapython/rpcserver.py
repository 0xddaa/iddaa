import socket
import thread
import cPickle
import sys
import idc
import idaapi
import idautils
from subprocess import Popen, PIPE
from iddaa.gdbsync import InfoCollector
from iddaa.utils import stdoutIO

debug = False
version = (1, 0, 0)
port = 56746
TMPDIR = 'C:\Windows\Temp'

class RPCServer(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = 'IDA RPC for remote gdb'
    help = ''
    wanted_name = 'RPC Server'
    wanted_hotkey = ''

    def init(self):
        print('RPC Server ({}) plugin has been loaded.'.format(utils.dump_version(version)))
        self.info_collector = InfoCollector()
        thread.start_new_thread(self.__init_rpc_server, ())
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass

    def __init_rpc_server(self):
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
            args = cmd.split()
            if 'GETSYM' == args[0]:
                csock.send(self.info_collector.get_symfile())
            elif 'GETPSEUDOCODE' == args[0]:
                if len(args) < 2:
                    csock.send('Miss function name.')
                    continue
                func = args[1]
                csock.send(self.info_collector.get_pseudo_code(func))
            elif 'GETLOCALTYPE' == args[0]:
                csock.send(cPickle.dumps(self.info_collector.get_local_type()))
            elif 'EXECFILE' == args[0]:
                code = csock.recv(1024)
                tmpfile = '{}\code.py'.format(TMPDIR)

                try:
                    f = open(tmpfile, 'w')
                    f.write(code.replace('\n', '\r\n'))
                    f.close()
                except:
                    print('[ERROR] Save tmp file failed.')
                    return

                with stdoutIO() as s:
                    exec open(tmpfile).read()
                csock.send(s.getvalue())
            elif 'EXEC' == args[0]:
                cmd = ' '.join(args[1:])
                with stdoutIO() as s:
                    exec 'print {}'.format(cmd)
                csock.send(s.getvalue())

            # Exception happened
            csock.close()

def PLUGIN_ENTRY():
    return RPCServer()
